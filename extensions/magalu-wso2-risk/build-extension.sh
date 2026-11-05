#!/usr/bin/env bash
set -euo pipefail
# Builds only against the exact running 7.3 GA distribution, without Bash 4 / GNU sha256sum.
here=$(cd "$(dirname "$0")" && pwd)
: "${WSO2_HOME:?WSO2_HOME must be the extracted exact GA 7.3 runtime home}"
: "${WSO2_GA_IMAGE_DIGEST:?Pin the exact GA 7.3 runtime image digest}"
plugins="$WSO2_HOME/repository/components/plugins"
lib="$WSO2_HOME/repository/components/lib"
dropins="$WSO2_HOME/repository/components/dropins"
[[ -d "$plugins" && -d "$lib" && "$WSO2_GA_IMAGE_DIGEST" == sha256:* ]] || { echo 'GA runtime preflight failed' >&2; exit 2; }
[[ "$(basename "$WSO2_HOME")" != *lab* ]] || exit 2
command -v python3 >/dev/null || { echo 'python3 missing' >&2; exit 2; }
# Bash 3.2 on macOS supports arrays and read -d ''; it lacks mapfile.
jars=()
while IFS= read -r -d '' jarpath; do
  jars+=("$jarpath")
done < <(find "$plugins" "$lib" -type f -name '*.jar' -print0)
((${#jars[@]} > 20)) || { echo 'WSO2 GA JAR inventory too small' >&2; exit 2; }
for required in \
  org/wso2/carbon/identity/application/authentication/framework/JsFunctionRegistry.class \
  org/wso2/carbon/identity/application/authentication/framework/config/model/graph/js/JsAuthenticationContext.class \
  org/wso2/carbon/identity/event/handler/AbstractEventHandler.class \
  org/osgi/service/component/ComponentContext.class \
  javax/servlet/http/HttpServletRequest.class; do
  found=0
  for j in "${jars[@]}"; do
    if unzip -Z1 "$j" "$required" 2>/dev/null | grep -Fqx "$required"; then
      found=1; break
    fi
  done
  ((found)) || { echo "Required GA class absent: $required" >&2; exit 3; }
done
pgjar=''
for j in "${jars[@]}"; do
  if [[ "$(basename "$j")" == postgresql*.jar ]]; then pgjar="$j"; break; fi
done
[[ -n "$pgjar" ]] || { echo 'GA PostgreSQL JDBC JAR not present' >&2; exit 3; }
# Fail closed unless we have exactly one SDK from the running WSO2 GA distribution.
[[ -d "$dropins" ]] || { echo 'GA Graal dropins directory missing' >&2; exit 3; }
graal_bundles=()
while IFS= read -r -d '' sdk; do
  graal_bundles+=("$sdk")
done < <(find "$dropins" -maxdepth 1 -type f -name 'graal-sdk-*.jar' -print0)
((${#graal_bundles[@]} == 1)) || { echo 'GA Graal SDK missing or ambiguous' >&2; exit 3; }
graal_bundle="${graal_bundles[0]}"
# Resolve Graal SDK without nesting a quoted heredoc inside $(...).
# macOS /bin/bash 3.2 misparses apostrophes in such nested heredocs.
# This standalone here-document is compatible with Bash 3.2.
mkdir -p "$here/target/evidence"
graal_cp_file="$here/target/evidence/ga-graal-classpath.txt"
python3 - "$graal_bundle" "$here/target/evidence/ga-graal-classes" "$graal_cp_file" <<'GRAAL_API_PY' || { echo 'GA Graal SDK classpath resolution failed' >&2; exit 3; }
import hashlib, io, pathlib, sys, zipfile
source, target, result = map(pathlib.Path, sys.argv[1:4])
required = {'org/graalvm/polyglot/Value.class',
            'org/graalvm/polyglot/proxy/ProxyExecutable.class'}
if not source.is_file() or source.is_symlink():
    raise SystemExit('GA Graal SDK missing or symlinked')
selected = []
found = set()
with zipfile.ZipFile(source) as outer:
    direct = required.intersection(outer.namelist())
    if direct:
        selected.append(source)
        found.update(direct)
    for name in sorted(n for n in outer.namelist() if n.endswith('.jar')):
        if found == required:
            break
        entry = outer.getinfo(name)
        if entry.file_size > 64 * 1024 * 1024:
            continue
        content = outer.read(name)
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as inner:
                contains = required.intersection(inner.namelist())
        except (zipfile.BadZipFile, OSError):
            continue
        if contains.difference(found):
            target.mkdir(parents=True, exist_ok=True)
            path = target / (hashlib.sha256(content).hexdigest()[:16] + '.jar')
            path.write_bytes(content)
            selected.append(path)
            found.update(contains)
if found != required:
    raise SystemExit('WSO2 GA Graal bundle lacks required Polyglot API classes')
result.write_text(':'.join(str(p) for p in selected) + '\n', encoding='utf-8')
GRAAL_API_PY
IFS= read -r graal_cp < "$graal_cp_file" || { echo 'GA Graal API classpath missing' >&2; exit 3; }
[[ -n "$graal_cp" ]] || { echo 'GA Graal API classpath empty' >&2; exit 3; }
cp=$(IFS=:; echo "${jars[*]}")
cp="$cp:$graal_cp"
mkdir -p "$here/target/bundle-classes" "$here/target/evidence"
# Do not use xargs for a source list that could be split into multiple javac calls.
sources=()
while IFS= read -r -d '' sourcepath; do
  sources+=("$sourcepath")
done < <(find "$here/src/main/java" -type f -name '*.java' -print0)
((${#sources[@]} > 0)) || { echo 'No Java sources' >&2; exit 3; }
javac --release 11 -encoding UTF-8 -cp "$cp" -d "$here/target/bundle-classes" "${sources[@]}"
cat > "$here/target/MANIFEST.MF" <<'MANIFEST'
Manifest-Version: 1.0
Bundle-ManifestVersion: 2
Bundle-SymbolicName: com.magalu.wso2.identity.risk
Bundle-Name: Magalu WSO2 GA Risk Enforcement
Bundle-Version: 0.1.0
Bundle-ClassPath: .,lib/postgresql.jar
Service-Component: OSGI-INF/magalu-risk.xml
Import-Package: org.osgi.framework,org.osgi.service.component,
 javax.servlet.http,
 org.wso2.carbon.identity.application.authentication.framework,
 org.wso2.carbon.identity.application.authentication.framework.config.
 model.graph.js,
 org.wso2.carbon.identity.application.authentication.framework.context
 ,org.wso2.carbon.identity.application.authentication.framework.util,
 org.wso2.carbon.identity.event,org.wso2.carbon.identity.event.event,
 org.wso2.carbon.identity.event.handler,org.graalvm.polyglot,
 org.graalvm.polyglot.proxy
MANIFEST
mkdir -p "$here/target/bundle-classes/lib"
cp "$pgjar" "$here/target/bundle-classes/lib/postgresql.jar"
jar --create --file "$here/target/magalu-wso2-risk-osgi.jar" \
 --manifest "$here/target/MANIFEST.MF" -C "$here/target/bundle-classes" . \
 -C "$here/src/main/resources" .
# The digest inventory is produced without assuming GNU sha256sum on macOS.
python3 - "$WSO2_GA_IMAGE_DIGEST" "$here/target/evidence/ga-dependency-inventory.txt" "$here/target/magalu-wso2-risk-osgi.jar" "${jars[@]}" "$graal_bundle" <<'PY'
import hashlib, pathlib, sys
image, output, bundle, *jars = sys.argv[1:]
with open(output, 'w', encoding='utf-8') as out:
    out.write('image_digest=' + image + '\n')
    for file in sorted(set(jars + [bundle])):
        h = hashlib.sha256()
        with open(file, 'rb') as f:
            for block in iter(lambda: f.read(1024 * 1024), b''):
                h.update(block)
        out.write(h.hexdigest() + '  ' + str(pathlib.Path(file).name) + '\n')
PY
echo 'Compiled against the supplied GA distribution. Activation and login enforcement remain UNVERIFIED.'
