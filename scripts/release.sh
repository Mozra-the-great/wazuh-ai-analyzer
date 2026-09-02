#!/usr/bin/env bash
# =============================================================================
# Wazuh AI Analyzer – Release-Helfer
#
# Regeneriert checksums.sha256 für analyzer.py, static/index.html und
# requirements.txt, setzt den Default-Wert von WAZUH_AI_REF in install.sh auf
# die übergebene Version und zeigt an, was noch zu tun ist.
#
# Wichtig: der Git-Tag wird ERST NACH diesem Skript (und einem Commit der
# Änderungen) gesetzt – der Tag zeigt also auf den Commit, der bereits den
# neuen Pin (WAZUH_AI_REF + checksums.sha256) enthält. Es gibt damit kein
# Henne-Ei-Problem: install.sh mit WAZUH_AI_REF=<version> lädt vom Tag
# <version>, und genau dieser Tag-Commit enthält die dazu passenden
# checksums.sha256.
#
# Usage: scripts/release.sh v1.0.1
# =============================================================================
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <version>  (z.B. v1.0.1)" >&2
    exit 1
fi

VERSION="$1"
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Fehler: Version muss dem Format vMAJOR.MINOR.PATCH entsprechen (erhalten: ${VERSION})" >&2
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"
cd "$REPO_ROOT"

for f in analyzer.py static/index.html requirements.txt; do
    [[ -f "$f" ]] || { echo "Fehler: '$f' nicht gefunden im Repo-Root" >&2; exit 1; }
done

echo "→ Regeneriere checksums.sha256 …"
sha256sum analyzer.py static/index.html requirements.txt > checksums.sha256
echo "  $(cat checksums.sha256 | tr '\n' ' ')"

echo "→ Setze WAZUH_AI_REF-Default in install.sh auf ${VERSION} …"
sed -i -E "s/^WAZUH_AI_REF=\"\\\$\{WAZUH_AI_REF:-[^}]*\}\"/WAZUH_AI_REF=\"\${WAZUH_AI_REF:-${VERSION}}\"/" install.sh

if ! grep -q "WAZUH_AI_REF:-${VERSION}}" install.sh; then
    echo "Fehler: WAZUH_AI_REF-Default in install.sh konnte nicht auf ${VERSION} gesetzt werden – Zeile nicht gefunden/Muster geändert?" >&2
    exit 1
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo " Diff:"
echo "═══════════════════════════════════════════════════════"
git --no-pager diff -- checksums.sha256 install.sh || true

echo ""
echo "═══════════════════════════════════════════════════════"
echo " Nächste Schritte:"
echo "═══════════════════════════════════════════════════════"
cat <<EOF
  git add checksums.sha256 install.sh
  git commit -m "chore(release): ${VERSION}"
  git tag ${VERSION}
  git push --tags
EOF
