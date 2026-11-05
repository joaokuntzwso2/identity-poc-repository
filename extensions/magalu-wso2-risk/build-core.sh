#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$here/target/classes" "$here/target/test-classes"
find "$here/src/main/java" -name '*.java' ! -name '*Wso2*' -print0 | xargs -0 javac --release 11 -encoding UTF-8 -d "$here/target/classes"
find "$here/src/test/java" -name '*.java' -print0 | xargs -0 javac --release 11 -encoding UTF-8 -cp "$here/target/classes" -d "$here/target/test-classes"
java -ea -cp "$here/target/classes:$here/target/test-classes" com.magalu.wso2.risk.AcceptanceTest
jar --create --file "$here/target/magalu-risk-core.jar" -C "$here/target/classes" .
