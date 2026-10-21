#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_MANAGER="$ROOT_DIR/backend/scripts/manage.sh"

usage() {
  cat <<'EOF'
Global Monitor 前后端管理脚本

用法：./manage.sh <命令>

  setup             初始化 Conda 后端环境和 .env
  start             启动 MySQL、ClickHouse、后端服务和前端
  start-local       仅启动本地模拟数据模式前端
  stop              停止前端和后端进程，保留数据库容器
  down              停止全部程序及数据库容器，保留数据库数据卷
  restart           重启完整前后端
  api-restart       仅重启 API，加载 .dev 与模型配置
  status            查询进程、API 健康状态和数据库容器状态
  logs [服务] [行数] 查看日志；服务可为 api/vector/collector/frontend/xdr-simulator
  seed              初始化 CMDB 和演示告警数据
  test              执行后端测试和运行时冒烟检查
  xdr-generate ...  生成指定类型的模拟告警
  help              显示本帮助

首次运行：
  ./manage.sh setup
  ./manage.sh start
  ./manage.sh seed

访问地址：前端 http://localhost:5173，后端接口文档 http://localhost:9528/docs
EOF
}

case "${1:-help}" in
  setup)
    command -v npm >/dev/null || { echo "error: 未找到 npm" >&2; exit 1; }
    "$BACKEND_MANAGER" env
    if [[ ! -d "$ROOT_DIR/node_modules" ]]; then
      (cd "$ROOT_DIR" && npm ci)
    fi
    echo "setup complete"
    ;;
  start)
    "$BACKEND_MANAGER" infra-up
    "$BACKEND_MANAGER" start
    if ! "$BACKEND_MANAGER" frontend; then
      "$BACKEND_MANAGER" stop
      exit 1
    fi
    echo "frontend: http://localhost:5173"
    echo "api docs: http://localhost:9528/docs"
    ;;
  start-local)
    "$BACKEND_MANAGER" frontend-local
    echo "frontend (local data): http://localhost:5173?dataMode=local"
    ;;
  stop) "$BACKEND_MANAGER" stop ;;
  down)
    "$BACKEND_MANAGER" stop
    "$BACKEND_MANAGER" infra-down
    ;;
  restart)
    "$BACKEND_MANAGER" stop
    "$0" start
    ;;
  api-restart) "$BACKEND_MANAGER" api-restart ;;
  status) "$BACKEND_MANAGER" status ;;
  logs)
    shift
    "$BACKEND_MANAGER" logs "$@"
    ;;
  seed) "$BACKEND_MANAGER" seed ;;
  test) "$BACKEND_MANAGER" test ;;
  xdr-generate)
    shift
    "$BACKEND_MANAGER" xdr-generate "$@"
    ;;
  help|-h|--help) usage ;;
  *)
    echo "error: 未知命令 $1" >&2
    usage >&2
    exit 2
    ;;
esac
