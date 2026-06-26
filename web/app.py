"""AgentRed Web UI - Flask 后端 API

提供 RESTful API 供前端调用，封装 Runner 执行引擎：
  - 配置 Agent 参数
  - 启动测试（异步执行）
  - 实时获取进度
  - 查看历史报告列表
  - 下载报告文件
"""

import io
import json
import logging
import os
import sys
import threading
import traceback
import uuid
from pathlib import Path
from datetime import datetime

from flask import (
    Flask, render_template, request, jsonify,
    send_from_directory, send_file, abort,
)

# Windows 编码兼容
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import yaml
from core.loader import load_all_testcases

# ============================================================
# Flask App 初始化
# ============================================================

app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "templates"),
    static_folder=str(Path(__file__).parent / "static"),
)

app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB 上传限制

# 配置日志
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("agentred-web")

# ============================================================
# Flask 全局错误处理器 — 确保所有错误返回 JSON
# ============================================================

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": str(e.description) if hasattr(e, 'description') else "Bad Request", "code": 400}), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": str(e.description) if hasattr(e, 'description') else "Not Found", "code": 404}), 404

@app.errorhandler(413)
def request_too_large(e):
    return jsonify({"error": "上传文件过大，最大限制 50MB", "code": 413}), 413

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "服务器内部错误", "code": 500}), 500

@app.errorhandler(Exception)
def handle_all_exceptions(e):
    logger.error(f"未处理的异常: {e}\n{traceback.format_exc()}")
    return jsonify({"error": str(e), "code": 500}), 500


# ============================================================
# 全局状态管理
# ============================================================

# 测试任务状态
tasks = {}  # task_id -> TaskState

REPORTS_DIR = PROJECT_ROOT / "reports"
UPLOADS_DIR = PROJECT_ROOT / "web" / "uploads"


class TaskState:
    """异步测试任务状态"""

    def __init__(self, task_id: str, config: dict):
        self.task_id = task_id
        self.config = config
        self.status = "pending"  # pending / running / completed / failed
        self.progress = 0        # 0-100
        self.current_stage = ""
        self.log_lines = []
        self.report = None
        self.report_path = None
        self.html_report_path = None
        self.error = None
        self.start_time = None
        self.end_time = None

    def add_log(self, line: str):
        self.log_lines.append(line)
        # 限制日志长度，避免内存过大
        if len(self.log_lines) > 2000:
            self.log_lines = self.log_lines[-1000:]

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "status": self.status,
            "progress": self.progress,
            "current_stage": self.current_stage,
            "log_lines": self.log_lines[-50:],  # 最近50行
            "error": self.error,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "report_summary": self._extract_summary() if self.report else None,
        }

    def _extract_summary(self) -> dict:
        if not self.report:
            return None
        summary = self.report.get("summary", {})
        return {
            "overall_score": summary.get("overall_score", 0),
            "risk_level": summary.get("risk_level", "unknown"),
            "static_score": summary.get("static_score"),
            "dynamic_score": summary.get("dynamic_score"),
            "duration_seconds": self.report.get("duration_seconds", 0),
            "agent_info": self.report.get("agent_info", {}),
            "recommendations_count": len(self.report.get("recommendations", [])),
            "config_issues_count": len(self.report.get("config_issues", [])),
        }


# ============================================================
# 辅助函数
# ============================================================

def load_config_file() -> dict:
    """加载默认配置"""
    config_path = PROJECT_ROOT / "config.yaml"
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {}


def build_runner_from_config(config: dict, user_params: dict) -> "Runner":
    """从用户参数构建 Runner"""

    from core.evaluator import RuleBasedEvaluator
    from core.runner import Runner
    from core.scorer import Scorer
    from core.reporter import Reporter

    agent_client = None

    # 如果有 API 参数，创建 client
    api_key = user_params.get("api_key", "")
    api_endpoint = user_params.get("api_endpoint", "")
    model = user_params.get("model", "")

    if api_key and api_endpoint:
        from client.openai_client import OpenAIClient

        agent_client = OpenAIClient(
            api_endpoint=api_endpoint,
            model=model or "gpt-4",
            api_key=api_key,
            timeout_seconds=config.get("agent", {}).get("timeout_seconds", 30),
            max_retries=config.get("agent", {}).get("max_retries", 2),
            name=user_params.get("agent_name", "target-agent"),
        )

    eval_cfg = config.get("evaluation", {})
    evaluator = RuleBasedEvaluator(
        default_refuse_keywords=eval_cfg.get("refuse_keywords", []),
        default_harmful_keywords=eval_cfg.get("harmful_indicators", []),
    )

    scorer = Scorer(
        dimension_weights=config.get("scoring", {}).get("weights"),
        severity_weights=config.get("scoring", {}).get("severity_weights"),
    )

    output_dir = str(REPORTS_DIR)
    reporter = Reporter(
        output_dir=output_dir,
        include_response_snippets=config.get("report", {}).get("include_response_snippets", True),
        snippet_max_length=config.get("report", {}).get("snippet_max_length", 200),
        agent_info=config.get("agent", {}),
    )

    # Advisor 参数
    advisor_api_key = user_params.get("advisor_api_key", "") or os.environ.get("ADVISOR_API_KEY", "")
    advisor_api_endpoint = user_params.get("advisor_api_endpoint", "")
    advisor_model = user_params.get("advisor_model", "")
    advisor_strategy = user_params.get("advisor_strategy", "auto")

    # 功能开关
    enable_advisor = user_params.get("enable_advisor", True)
    enable_config_checker = user_params.get("enable_config_checker", True)
    enable_extended_eval = user_params.get("enable_extended_eval", True)
    enable_tool_use = user_params.get("enable_tool_use", True)
    enable_adaptive = user_params.get("enable_adaptive", True)

    # 隐私参数
    privacy_level = user_params.get("privacy_level", "moderate")
    use_sanitized_advisor = user_params.get("use_sanitized_advisor", True)

    return Runner(
        agent_client=agent_client,
        evaluator=evaluator,
        scorer=scorer,
        reporter=reporter,
        advisor_api_key=advisor_api_key,
        advisor_api_endpoint=advisor_api_endpoint,
        advisor_model=advisor_model,
        advisor_strategy=advisor_strategy,
        enable_advisor=enable_advisor,
        enable_config_checker=enable_config_checker,
        enable_extended_eval=enable_extended_eval,
        enable_tool_use=enable_tool_use,
        privacy_level=privacy_level,
        use_sanitized_advisor=use_sanitized_advisor,
        enable_adaptive=enable_adaptive,
    )


class LogCapture:
    """安全地捕获 Runner 的 print 输出（不替换 builtins.print）"""

    def __init__(self, task_state: TaskState):
        self.task_state = task_state
        self._buffer = io.StringIO()
        self._original_stdout = sys.stdout

    def write(self, text):
        # 同时写入原始 stdout 和捕获缓冲区
        self._original_stdout.write(text)
        if text and text.strip():
            self.task_state.add_log(text.rstrip("\n"))
            self._update_progress(text)

    def _update_progress(self, line: str):
        """根据日志内容推断阶段"""
        if "阶段 0" in line or "配置缺失检测" in line:
            self.task_state.current_stage = "配置检测"
            self.task_state.progress = max(self.task_state.progress, 10)
        elif "阶段 1" in line or "静态分析" in line:
            self.task_state.current_stage = "静态分析"
            self.task_state.progress = max(self.task_state.progress, 20)
        elif "阶段 1.5" in line or "自适应" in line:
            self.task_state.current_stage = "自适应生成"
            self.task_state.progress = max(self.task_state.progress, 30)
        elif "阶段 2" in line or "Tool Use" in line:
            self.task_state.current_stage = "Tool Use 测试"
            self.task_state.progress = max(self.task_state.progress, 40)
        elif "阶段 3" in line or "动态测试" in line:
            self.task_state.current_stage = "动态测试"
            self.task_state.progress = max(self.task_state.progress, 50)
        elif "阶段 4" in line or "RAG" in line:
            self.task_state.current_stage = "RAG/Memory 评估"
            self.task_state.progress = max(self.task_state.progress, 65)
        elif "阶段 5" in line or "Advisor" in line:
            self.task_state.current_stage = "Advisor 分析"
            self.task_state.progress = max(self.task_state.progress, 75)
        elif "阶段 6" in line or "脱敏" in line:
            self.task_state.current_stage = "报告脱敏"
            self.task_state.progress = max(self.task_state.progress, 85)
        elif "最终" in line or "评分摘要" in line:
            self.task_state.current_stage = "完成"
            self.task_state.progress = max(self.task_state.progress, 95)

    def flush(self):
        self._original_stdout.flush()
        self._buffer.flush()

    def getvalue(self):
        return self._buffer.getvalue()

    def install(self):
        """替换 sys.stdout（线程安全的，只影响当前线程的输出）"""
        sys.stdout = self

    def restore(self):
        """恢复原始 sys.stdout"""
        sys.stdout = self._original_stdout


def run_test_async(task_state: TaskState, config: dict, user_params: dict):
    """异步执行测试任务"""

    task_state.status = "running"
    task_state.start_time = datetime.now().isoformat()

    # 使用 LogCapture 代替 builtins.print 替换
    log_capture = LogCapture(task_state)

    try:
        # 构建 Runner
        task_state.add_log("⚙️ 正在初始化测试引擎...")
        task_state.progress = 5
        task_state.current_stage = "初始化"

        runner = build_runner_from_config(config, user_params)

        # 处理上传的 Agent 目录
        agent_dir = user_params.get("agent_dir", "")
        agent_prompt = user_params.get("agent_prompt", "")
        agent_name = user_params.get("agent_name", "my-agent")

        # 上传文件处理
        uploaded_file = user_params.get("uploaded_file", "")
        uploaded_results = None
        if uploaded_file:
            try:
                with open(uploaded_file, "r", encoding="utf-8") as f:
                    upload_data = json.load(f)
                if isinstance(upload_data, list):
                    uploaded_results = upload_data
                elif isinstance(upload_data, dict):
                    uploaded_results = upload_data.get("tool_results", [upload_data])
                task_state.add_log(f"📂 已加载上传结果: {len(uploaded_results)} 条")
            except Exception as e:
                task_state.add_log(f"⚠️ 上传文件读取失败: {e}")

        # 执行测试
        task_state.add_log("🚀 开始执行测试...")
        task_state.progress = 10

        # 安装日志捕获（线程安全）
        log_capture.install()

        try:
            dimension_filter = None if user_params.get("dimension", "all") == "all" else user_params.get("dimension")
            severity_filter = user_params.get("severity", "").split(",") if user_params.get("severity") else None

            report = runner.run(
                testcases_dir=str(PROJECT_ROOT / "testcases"),
                dimension_filter=dimension_filter,
                category_filter=user_params.get("category"),
                severity_filter=severity_filter,
                verbose=True,
                agent_dir=agent_dir,
                agent_prompt=agent_prompt,
                agent_name=agent_name,
                config_data=config,
                uploaded_results=uploaded_results,
            )
        finally:
            # 确保恢复 stdout
            log_capture.restore()

        # 保存报告
        task_state.add_log("💾 正在保存报告...")
        task_state.progress = 95

        json_path = runner.reporter.save_report(report)
        html_path = runner.reporter.save_html_report(report)

        task_state.report = report
        task_state.report_path = json_path
        task_state.html_report_path = html_path
        task_state.status = "completed"
        task_state.progress = 100
        task_state.current_stage = "已完成"
        task_state.end_time = datetime.now().isoformat()

        task_state.add_log(f"✅ 测试完成！综合评分: {report.get('summary', {}).get('overall_score', 0)}/100")
        task_state.add_log(f"📄 JSON 报告: {json_path}")
        task_state.add_log(f"📄 HTML 报告: {html_path}")

        logger.info(f"测试任务 {task_state.task_id} 完成, 评分: {report.get('summary', {}).get('overall_score', 0)}")

    except Exception as e:
        # 确保恢复 stdout
        log_capture.restore()

        task_state.status = "failed"
        task_state.error = str(e)
        task_state.end_time = datetime.now().isoformat()
        task_state.add_log(f"❌ 测试执行失败: {e}")
        task_state.add_log(traceback.format_exc()[-800:])
        logger.error(f"测试任务 {task_state.task_id} 失败: {e}\n{traceback.format_exc()}")


def safe_extract_zip(zip_path: Path, extract_dir: Path) -> str:
    """安全解压 ZIP 文件，防止路径穿越攻击"""
    import zipfile

    extract_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(str(zip_path), "r") as zf:
        # 安全检查：防止路径穿越
        for member in zf.namelist():
            member_path = (extract_dir / member).resolve()
            if not str(member_path).startswith(str(extract_dir.resolve())):
                raise ValueError(f"ZIP 包含危险路径: {member}")

        # 安全解压
        zf.extractall(str(extract_dir))

    # 检查解压后目录是否有内容
    contents = list(extract_dir.iterdir())
    if len(contents) == 1 and contents[0].is_dir():
        # 如果 ZIP 只包含一个根目录，使用该目录作为 agent_dir
        return str(contents[0])

    return str(extract_dir)


# ============================================================
# API 路由
# ============================================================

@app.route("/")
def index():
    """首页 - 配置与启动测试"""
    return render_template("index.html")


@app.route("/results")
def results_page():
    """结果页 - 历史报告列表"""
    return render_template("results.html")


@app.route("/api/health")
def api_health():
    """服务器健康检查"""
    return jsonify({
        "status": "ok",
        "version": "5.1",
        "project_root": str(PROJECT_ROOT),
        "tasks_running": sum(1 for t in tasks.values() if t.status == "running"),
        "tasks_total": len(tasks),
    })


@app.route("/api/testcases")
def api_testcases():
    """获取测试用例统计"""
    testcases_dir = str(PROJECT_ROOT / "testcases")
    all_cases = load_all_testcases(testcases_dir)

    stats = {
        "total": len(all_cases),
        "by_dimension": {},
        "by_severity": {},
        "by_category": {},
    }

    for case in all_cases:
        dim = case.dimension
        sev = case.severity
        cat = case.category

        stats["by_dimension"][dim] = stats["by_dimension"].get(dim, 0) + 1
        stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
        stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

    return jsonify(stats)


@app.route("/api/testcases/list")
def api_testcases_list():
    """获取测试用例详细列表（分页）"""
    testcases_dir = str(PROJECT_ROOT / "testcases")
    all_cases = load_all_testcases(testcases_dir)

    # 过滤
    dimension = request.args.get("dimension")
    severity = request.args.get("severity")
    category = request.args.get("category")
    search = request.args.get("search", "").lower()

    filtered = all_cases
    if dimension:
        filtered = [c for c in filtered if c.dimension == dimension]
    if severity:
        filtered = [c for c in filtered if c.severity == severity]
    if category:
        filtered = [c for c in filtered if c.category == category]
    if search:
        filtered = [c for c in filtered if search in c.id.lower() or search in c.description.lower() or search in c.category.lower()]

    # 分页
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    total = len(filtered)
    start = (page - 1) * per_page
    end = start + per_page
    page_cases = filtered[start:end]

    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "cases": [
            {
                "id": c.id,
                "dimension": c.dimension,
                "category": c.category,
                "severity": c.severity,
                "description": c.description,
                "prompt_preview": c.prompt[:100] + "..." if len(c.prompt) > 100 else c.prompt,
                "reference": c.reference,
            }
            for c in page_cases
        ],
    })


@app.route("/api/start", methods=["POST"])
def api_start_test():
    """启动测试任务"""

    try:
        data = request.get_json(silent=True) or {}
        files = request.files

        # 处理上传文件（Agent 目录 zip 或结果 JSON）
        uploaded_file_path = ""
        if "upload_file" in files:
            upload_file = files["upload_file"]
            filename = upload_file.filename
            # 安全文件名
            safe_name = Path(filename).name
            save_path = UPLOADS_DIR / f"{uuid.uuid4().hex[:8]}_{safe_name}"
            UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
            upload_file.save(str(save_path))
            uploaded_file_path = str(save_path)

        # 处理 Agent 目录上传（zip）
        agent_dir = ""
        if "agent_zip" in files:
            zip_file = files["agent_zip"]
            safe_name = Path(zip_file.filename).name
            zip_path = UPLOADS_DIR / f"{uuid.uuid4().hex[:8]}_{safe_name}"
            UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
            zip_file.save(str(zip_path))

            # 安全解压
            extract_dir = UPLOADS_DIR / f"agent_{uuid.uuid4().hex[:8]}"
            try:
                agent_dir = safe_extract_zip(zip_path, extract_dir)
                logger.info(f"ZIP 解压成功: {zip_path} -> {agent_dir}")
            except Exception as e:
                logger.error(f"ZIP 解压失败: {e}")
                return jsonify({"error": f"ZIP 文件解压失败: {e}", "code": 400}), 400

        # 从表单数据收集参数
        user_params = {
            "agent_name": data.get("agent_name", request.form.get("agent_name", "my-agent")),
            "agent_dir": agent_dir or data.get("agent_dir", request.form.get("agent_dir", "")),
            "agent_prompt": data.get("agent_prompt", request.form.get("agent_prompt", "")),
            "api_key": data.get("api_key", request.form.get("api_key", "")),
            "api_endpoint": data.get("api_endpoint", request.form.get("api_endpoint", "")),
            "model": data.get("model", request.form.get("model", "gpt-4")),
            "dimension": data.get("dimension", request.form.get("dimension", "all")),
            "category": data.get("category", request.form.get("category", "")),
            "severity": data.get("severity", request.form.get("severity", "")),
            # Advisor 参数
            "advisor_api_key": data.get("advisor_api_key", request.form.get("advisor_api_key", "")),
            "advisor_api_endpoint": data.get("advisor_api_endpoint", request.form.get("advisor_api_endpoint", "")),
            "advisor_model": data.get("advisor_model", request.form.get("advisor_model", "")),
            "advisor_strategy": data.get("advisor_strategy", request.form.get("advisor_strategy", "auto")),
            # 功能开关
            "enable_advisor": _to_bool(data.get("enable_advisor", request.form.get("enable_advisor", "true"))),
            "enable_config_checker": _to_bool(data.get("enable_config_checker", request.form.get("enable_config_checker", "true"))),
            "enable_extended_eval": _to_bool(data.get("enable_extended_eval", request.form.get("enable_extended_eval", "true"))),
            "enable_tool_use": _to_bool(data.get("enable_tool_use", request.form.get("enable_tool_use", "true"))),
            "enable_adaptive": _to_bool(data.get("enable_adaptive", request.form.get("enable_adaptive", "true"))),
            # 隐私参数
            "privacy_level": data.get("privacy_level", request.form.get("privacy_level", "moderate")),
            "use_sanitized_advisor": _to_bool(data.get("use_sanitized_advisor", request.form.get("use_sanitized_advisor", "true"))),
            # 上传文件
            "uploaded_file": uploaded_file_path,
        }

        # 加载配置
        config = load_config_file()

        # CLI 参数覆盖配置
        if user_params.get("api_key"):
            config.setdefault("agent", {})["api_key"] = user_params["api_key"]
        if user_params.get("api_endpoint"):
            config.setdefault("agent", {})["api_endpoint"] = user_params["api_endpoint"]
        if user_params.get("model"):
            config.setdefault("agent", {})["model"] = user_params["model"]

        # 创建任务
        task_id = uuid.uuid4().hex[:12]
        task_state = TaskState(task_id, config)
        tasks[task_id] = task_state

        # 异步执行
        thread = threading.Thread(
            target=run_test_async,
            args=(task_state, config, user_params),
            daemon=True,
        )
        thread.start()

        logger.info(f"测试任务 {task_id} 已启动, agent: {user_params.get('agent_name')}")

        return jsonify({"task_id": task_id, "status": "started"})

    except Exception as e:
        logger.error(f"启动测试失败: {e}\n{traceback.format_exc()}")
        return jsonify({"error": str(e), "code": 500}), 500


@app.route("/api/task/<task_id>")
def api_task_status(task_id):
    """获取任务状态"""
    task = tasks.get(task_id)
    if not task:
        return jsonify({"error": "任务不存在", "code": 404}), 404

    return jsonify(task.to_dict())


@app.route("/api/task/<task_id>/logs")
def api_task_logs(task_id):
    """获取完整日志"""
    task = tasks.get(task_id)
    if not task:
        return jsonify({"error": "任务不存在", "code": 404}), 404

    offset = int(request.args.get("offset", 0))
    logs = task.log_lines[offset:]

    return jsonify({
        "task_id": task_id,
        "total_logs": len(task.log_lines),
        "offset": offset,
        "logs": logs,
    })


@app.route("/api/task/<task_id>/report")
def api_task_report(task_id):
    """获取完整报告数据"""
    task = tasks.get(task_id)
    if not task:
        return jsonify({"error": "任务不存在", "code": 404}), 404

    if task.status != "completed":
        return jsonify({"error": "任务尚未完成", "status": task.status})

    return jsonify(task.report)


@app.route("/api/task/<task_id>/html_report")
def api_task_html_report(task_id):
    """获取 HTML 报告文件"""
    task = tasks.get(task_id)
    if not task:
        return jsonify({"error": "任务不存在", "code": 404}), 404

    if task.status != "completed" or not task.html_report_path:
        return jsonify({"error": "报告尚未生成", "status": task.status})

    return send_file(task.html_report_path, as_attachment=False)


@app.route("/api/reports")
def api_reports_list():
    """获取历史报告列表"""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    reports = []
    for f in REPORTS_DIR.glob("*.json"):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            summary = data.get("summary", {})
            agent_info = data.get("agent_info", {})
            reports.append({
                "filename": f.name,
                "report_id": data.get("report_id", ""),
                "timestamp": data.get("timestamp", ""),
                "agent_name": agent_info.get("name", "unknown"),
                "framework": agent_info.get("framework", "unknown"),
                "overall_score": summary.get("overall_score", 0),
                "risk_level": summary.get("risk_level", "unknown"),
                "duration_seconds": data.get("duration_seconds", 0),
            })
        except Exception:
            continue

    # 按时间倒序
    reports.sort(key=lambda r: r.get("timestamp", ""), reverse=True)

    return jsonify({"reports": reports, "total": len(reports)})


@app.route("/api/reports/<filename>")
def api_report_detail(filename):
    """获取指定报告详情"""
    filepath = REPORTS_DIR / filename
    if not filepath.exists():
        return jsonify({"error": "报告文件不存在", "code": 404}), 404

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/api/reports/<filename>/download")
def api_report_download(filename):
    """下载报告文件"""
    filepath = REPORTS_DIR / filename
    if not filepath.exists():
        return jsonify({"error": "报告文件不存在", "code": 404}), 404

    return send_file(str(filepath), as_attachment=True)


@app.route("/api/reports/<filename>/html")
def api_report_html(filename):
    """查看 HTML 报告"""
    # 找对应的 HTML 文件
    html_name = filename.replace(".json", ".html")
    html_path = REPORTS_DIR / html_name

    if not html_path.exists():
        return jsonify({"error": "HTML 报告不存在", "code": 404}), 404

    return send_file(str(html_path), as_attachment=False)


@app.route("/api/config")
def api_config():
    """获取当前默认配置"""
    config = load_config_file()
    # 脱敏 API Key
    if "agent" in config and "api_key" in config["agent"]:
        key = config["agent"]["api_key"]
        if key and not key.startswith("${"):
            config["agent"]["api_key"] = key[:8] + "..." if len(key) > 8 else "***"
    return jsonify(config)


def _to_bool(val) -> bool:
    """将各种形式转为 bool"""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes", "on")
    return bool(val)


# ============================================================
# 启动入口
# ============================================================

def main():
    """启动 Web UI 服务器"""
    import argparse

    parser = argparse.ArgumentParser(description="AgentRed Web UI")
    parser.add_argument("--host", default="127.0.0.1", help="服务器地址")
    parser.add_argument("--port", type=int, default=5000, help="服务器端口")
    parser.add_argument("--debug", action="store_true", help="开发模式")
    args = parser.parse_args()

    print(f"\n  🔥 AgentRed Web UI 启动")
    print(f"  📍 http://{args.host}:{args.port}")
    print(f"  📂 项目目录: {PROJECT_ROOT}")
    print()

    # 使用 threaded=True 确保 Flask 能同时处理请求和进度轮询
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
