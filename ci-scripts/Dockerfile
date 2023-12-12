FROM jenkins-agent/bullseye

RUN apt-get update && \
    apt-get install -y \
				docker.io \
                # poetry depends on that the python executable exists...
				python-is-python3 \
				python3-dev \
				python3-pip \
    && rm -rf /var/lib/apt/lists/*
