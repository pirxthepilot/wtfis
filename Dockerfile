####################################
# Builder image
####################################

FROM python:3.10-slim as builder

WORKDIR /workspace
COPY . .

# Install git
RUN apt-get update && \
    apt-get install -y --no-install-recommends git

# Checkout latest tagged commit
RUN git checkout \
        tags/$(git describe --tags $(git rev-list --tags --max-count=1)) \
        -b latest_tag

# Ensure latest pip
RUN python -m pip install --upgrade pip

# Install hatch
RUN pip install hatch

# Clean build wheel and src tarball
RUN hatch build --clean


####################################
# Final image
####################################

FROM python:3.10-slim

# Create user and cd to work dir
RUN useradd --create-home --shell /bin/bash wtfis
WORKDIR /home/wtfis

# Copy wheel file from builder image
COPY --from=builder /workspace/dist/*.whl .

# Upgrade pip, install wheel and delete wheel file
RUN python -m pip install --upgrade pip && \
    pip install *.whl && \
    rm -f *.whl

# Run as user
USER wtfis

# Command
CMD ["bash"]
