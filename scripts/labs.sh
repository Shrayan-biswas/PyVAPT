#!/usr/bin/env bash
# Manage local practice targets (all bound to 127.0.0.1 only).
#   ./scripts/labs.sh start|stop|reset|status [juice-shop|dvwa|webgoat ...]
set -euo pipefail
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

declare -A IMAGE=( [juice-shop]="bkimminich/juice-shop" [dvwa]="vulnerables/web-dvwa" [webgoat]="webgoat/webgoat" )
declare -A PORTS=( [juice-shop]="127.0.0.1:3000:3000" [dvwa]="127.0.0.1:8081:80" [webgoat]="127.0.0.1:8082:8080" )
declare -A URL=(   [juice-shop]="http://127.0.0.1:3000" [dvwa]="http://127.0.0.1:8081 (open /setup.php once, login admin/password)" [webgoat]="http://127.0.0.1:8082/WebGoat" )

cmd="${1:-status}"; shift || true
names=("$@"); [ ${#names[@]} -eq 0 ] && names=(juice-shop dvwa webgoat)
for n in "${names[@]}"; do
  [[ -v IMAGE[$n] ]] || { echo "unknown lab: $n (choose: ${!IMAGE[*]})"; exit 1; }
done

start_one() {
  local n=$1
  if $SUDO docker inspect "$n" >/dev/null 2>&1; then $SUDO docker start "$n" >/dev/null
  else $SUDO docker run -d --name "$n" -p "${PORTS[$n]}" "${IMAGE[$n]}" >/dev/null; fi
  echo "started $n -> ${URL[$n]}"
}

case "$cmd" in
  start)  for n in "${names[@]}"; do start_one "$n"; done ;;
  stop)   for n in "${names[@]}"; do $SUDO docker stop "$n" >/dev/null 2>&1 && echo "stopped $n" || echo "$n not running"; done ;;
  reset)  for n in "${names[@]}"; do $SUDO docker rm -f "$n" >/dev/null 2>&1 || true; start_one "$n"; done ;;
  status) $SUDO docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | grep -E "NAMES|$(IFS='|'; echo "${names[*]}")" || true ;;
  *) echo "usage: $0 start|stop|reset|status [lab ...]"; exit 1 ;;
esac
