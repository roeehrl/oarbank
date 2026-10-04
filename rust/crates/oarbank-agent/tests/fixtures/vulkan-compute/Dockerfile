# A Vulkan compute probe for GPU containers (docs/design/gpu-placement.md): Mesa's Vulkan drivers (Venus for the macOS
# krunkit VM, the AMD and Intel drivers, lavapipe), vulkaninfo, and vkcompute, which runs one compute shader.
# Venus under krunkit needs the libkrun build of Mesa (Fedora's own fails vkCreateInstance there), pinned as RamaLama does.
FROM registry.fedoraproject.org/fedora:44
ARG MESA_VULKAN_VERSION=25.3.6-102.fc44
RUN dnf -y install --setopt=install_weak_deps=False dnf-plugins-core 'dnf-command(versionlock)' && \
    dnf -y copr enable slp/mesa-libkrun-vulkan && \
    dnf -y install --setopt=install_weak_deps=False mesa-vulkan-drivers-$MESA_VULKAN_VERSION vulkan-loader \
        vulkan-loader-devel vulkan-headers vulkan-tools gcc glslc && \
    dnf versionlock add mesa-vulkan-drivers-$MESA_VULKAN_VERSION && dnf clean all
COPY vkcompute.c double.comp /src/
RUN glslc /src/double.comp -o /usr/local/share/double.spv && gcc -O2 -Wall -o /usr/local/bin/vkcompute /src/vkcompute.c -lvulkan
