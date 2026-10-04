# A Vulkan compute probe for GPU containers (docs/design/gpu-placement.md): Mesa's Vulkan drivers (Venus for the macOS
# krunkit VM, the AMD and Intel drivers, lavapipe), vulkaninfo, and vkcompute, which runs one compute shader.
FROM registry.fedoraproject.org/fedora:44
RUN dnf -y install --setopt=install_weak_deps=False mesa-vulkan-drivers vulkan-loader vulkan-loader-devel vulkan-headers \
        vulkan-tools gcc glslc && dnf clean all
COPY vkcompute.c double.comp /src/
RUN glslc /src/double.comp -o /usr/local/share/double.spv && gcc -O2 -Wall -o /usr/local/bin/vkcompute /src/vkcompute.c -lvulkan
