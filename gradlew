#!/bin/sh
#
# Gradle wrapper script for POSIX systems.
#

APP_HOME=$( cd "${0%/*}/.." && pwd -P )
APP_NAME="Gradle"
APP_BASE_NAME=${0##*/}
DEFAULT_JVM_OPTS='"-Xmx64m" "-Xms64m"'

CLASSPATH=$APP_HOME/gradle/wrapper/gradle-wrapper.jar

if [ -n "$JAVA_HOME" ] ; then
    JAVACMD=$JAVA_HOME/bin/java
else
    JAVACMD=java
fi

# Download gradle-wrapper.jar if missing
if [ ! -f "$CLASSPATH" ]; then
    mkdir -p "$APP_HOME/gradle/wrapper"
    echo "Downloading gradle-wrapper.jar..."
    curl -fsSL -o "$CLASSPATH" \
      "https://raw.githubusercontent.com/gradle/gradle/v8.2.0/gradle/wrapper/gradle-wrapper.jar" \
      || wget -q -O "$CLASSPATH" \
      "https://raw.githubusercontent.com/gradle/gradle/v8.2.0/gradle/wrapper/gradle-wrapper.jar"
fi

eval "set -- $(
    printf '%s\n' "$DEFAULT_JVM_OPTS" |
    xargs -n1 |
    sed 's~[^a-zA-Z0-9/=@._-]~\\&~g' |
    tr '\n' ' '
) $(printf '%q ' \
    "-Dorg.gradle.appname=$APP_BASE_NAME" \
    -classpath "$CLASSPATH" \
    org.gradle.wrapper.GradleWrapperMain \
    "$@")"

exec "$JAVACMD" "$@"
