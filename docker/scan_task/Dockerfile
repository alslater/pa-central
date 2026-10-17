FROM python:3.12-slim
ARG UV_VERSION=0.13.1
ARG NODE_VERSION=24.22.0
RUN apt-get update && apt-get install -y --no-install-recommends git openssh-client ca-certificates curl xz-utils \
 && case "$(dpkg --print-architecture)" in amd64) NODE_ARCH=x64 ;; arm64) NODE_ARCH=arm64 ;; \
      *) echo "unsupported architecture" >&2; exit 1 ;; esac \
 && NODE_TAR="node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz" \
 && curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/${NODE_TAR}" \
 && curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt" \
 && grep " ${NODE_TAR}$" SHASUMS256.txt | sha256sum -c - \
 && tar -xJf "${NODE_TAR}" -C /usr/local --strip-components=1 \
 && rm -f "${NODE_TAR}" SHASUMS256.txt \
 && apt-get purge -y curl xz-utils && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "uv==${UV_VERSION}"
# The unprivileged user pa fix runs as (docs/fix-plans-deployment.md): its home holds only
# what the task writes there, never the task's own secrets. -k /dev/null: no skeleton dotfiles.
RUN groupadd -g 10001 pa-trial && useradd -u 10001 -g 10001 -m -k /dev/null -d /home/pa-trial -s /usr/sbin/nologin pa-trial
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY scan_task.py fix_plan.py ./
RUN chmod 0700 /app
CMD ["python", "scan_task.py"]
