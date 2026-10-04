/* vkcompute: run one compute shader (double.spv: v[i] = 2 v[i] + 1) on the first Vulkan device that is not a CPU device
 * (or any device with VKCOMPUTE_ALLOW_CPU=1, for a check on lavapipe), and check every element. Prints the device and
 * "compute: ok <n>", exit 0; anything else is a failure. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vulkan/vulkan.h>

#define N 65536
#define CHECK(x) do { VkResult r_ = (x); if (r_ != VK_SUCCESS) { fprintf(stderr, "%s failed: %d\n", #x, r_); return 1; } } while (0)

static const char *type_name(VkPhysicalDeviceType t) {
    switch (t) {
    case VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU: return "integrated";
    case VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU: return "discrete";
    case VK_PHYSICAL_DEVICE_TYPE_VIRTUAL_GPU: return "virtual";
    case VK_PHYSICAL_DEVICE_TYPE_CPU: return "cpu";
    default: return "other";
    }
}

int main(void) {
    int allow_cpu = getenv("VKCOMPUTE_ALLOW_CPU") != NULL;
    VkApplicationInfo app = {VK_STRUCTURE_TYPE_APPLICATION_INFO, NULL, "vkcompute", 1, "oarbank", 1, VK_API_VERSION_1_1};
    VkInstanceCreateInfo ici = {VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, NULL, 0, &app, 0, NULL, 0, NULL};
    VkInstance inst;
    CHECK(vkCreateInstance(&ici, NULL, &inst));

    uint32_t n = 0;
    CHECK(vkEnumeratePhysicalDevices(inst, &n, NULL));
    VkPhysicalDevice devs[16];
    if (n > 16) n = 16;
    CHECK(vkEnumeratePhysicalDevices(inst, &n, devs));
    VkPhysicalDevice pd = VK_NULL_HANDLE;
    uint32_t family = 0;
    VkPhysicalDeviceProperties props;
    for (uint32_t i = 0; i < n && pd == VK_NULL_HANDLE; i++) {
        vkGetPhysicalDeviceProperties(devs[i], &props);
        if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_CPU && !allow_cpu) continue;
        uint32_t q = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(devs[i], &q, NULL);
        VkQueueFamilyProperties fams[16];
        if (q > 16) q = 16;
        vkGetPhysicalDeviceQueueFamilyProperties(devs[i], &q, fams);
        for (uint32_t f = 0; f < q; f++) {
            if (fams[f].queueFlags & VK_QUEUE_COMPUTE_BIT) { pd = devs[i]; family = f; break; }
        }
    }
    if (pd == VK_NULL_HANDLE) { fprintf(stderr, "no Vulkan GPU device with a compute queue (%u devices)\n", n); return 1; }
    printf("device: %s (%s)\n", props.deviceName, type_name(props.deviceType));

    float prio = 1.0f;
    VkDeviceQueueCreateInfo qci = {VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO, NULL, 0, family, 1, &prio};
    VkDeviceCreateInfo dci = {VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO, NULL, 0, 1, &qci, 0, NULL, 0, NULL, NULL};
    VkDevice dev;
    CHECK(vkCreateDevice(pd, &dci, NULL, &dev));
    VkQueue queue;
    vkGetDeviceQueue(dev, family, 0, &queue);

    VkBufferCreateInfo bci = {VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, NULL, 0, N * sizeof(uint32_t),
                              VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, VK_SHARING_MODE_EXCLUSIVE, 0, NULL};
    VkBuffer buf;
    CHECK(vkCreateBuffer(dev, &bci, NULL, &buf));
    VkMemoryRequirements req;
    vkGetBufferMemoryRequirements(dev, buf, &req);
    VkPhysicalDeviceMemoryProperties mp;
    vkGetPhysicalDeviceMemoryProperties(pd, &mp);
    uint32_t want = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, type = UINT32_MAX;
    for (uint32_t i = 0; i < mp.memoryTypeCount; i++)
        if ((req.memoryTypeBits & (1u << i)) && (mp.memoryTypes[i].propertyFlags & want) == want) { type = i; break; }
    if (type == UINT32_MAX) { fprintf(stderr, "no host-visible coherent memory\n"); return 1; }
    VkMemoryAllocateInfo mai = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, NULL, req.size, type};
    VkDeviceMemory mem;
    CHECK(vkAllocateMemory(dev, &mai, NULL, &mem));
    CHECK(vkBindBufferMemory(dev, buf, mem, 0));
    uint32_t *data;
    CHECK(vkMapMemory(dev, mem, 0, VK_WHOLE_SIZE, 0, (void **)&data));
    for (uint32_t i = 0; i < N; i++) data[i] = i;

    FILE *f = fopen("/usr/local/share/double.spv", "rb");
    if (!f) { perror("double.spv"); return 1; }
    static uint32_t code[16384];
    size_t len = fread(code, 1, sizeof code, f);
    fclose(f);
    VkShaderModuleCreateInfo smci = {VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO, NULL, 0, len, code};
    VkShaderModule sm;
    CHECK(vkCreateShaderModule(dev, &smci, NULL, &sm));

    VkDescriptorSetLayoutBinding b = {0, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1, VK_SHADER_STAGE_COMPUTE_BIT, NULL};
    VkDescriptorSetLayoutCreateInfo dslci = {VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO, NULL, 0, 1, &b};
    VkDescriptorSetLayout dsl;
    CHECK(vkCreateDescriptorSetLayout(dev, &dslci, NULL, &dsl));
    VkPipelineLayoutCreateInfo plci = {VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO, NULL, 0, 1, &dsl, 0, NULL};
    VkPipelineLayout pl;
    CHECK(vkCreatePipelineLayout(dev, &plci, NULL, &pl));
    VkComputePipelineCreateInfo cpci = {VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO, NULL, 0,
        {VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO, NULL, 0, VK_SHADER_STAGE_COMPUTE_BIT, sm, "main", NULL},
        pl, VK_NULL_HANDLE, -1};
    VkPipeline pipe;
    CHECK(vkCreateComputePipelines(dev, VK_NULL_HANDLE, 1, &cpci, NULL, &pipe));

    VkDescriptorPoolSize ps = {VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1};
    VkDescriptorPoolCreateInfo dpci = {VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO, NULL, 0, 1, 1, &ps};
    VkDescriptorPool dp;
    CHECK(vkCreateDescriptorPool(dev, &dpci, NULL, &dp));
    VkDescriptorSetAllocateInfo dsai = {VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO, NULL, dp, 1, &dsl};
    VkDescriptorSet ds;
    CHECK(vkAllocateDescriptorSets(dev, &dsai, &ds));
    VkDescriptorBufferInfo dbi = {buf, 0, VK_WHOLE_SIZE};
    VkWriteDescriptorSet w = {VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET, NULL, ds, 0, 0, 1, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, NULL, &dbi, NULL};
    vkUpdateDescriptorSets(dev, 1, &w, 0, NULL);

    VkCommandPoolCreateInfo cpi = {VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, NULL, 0, family};
    VkCommandPool cp;
    CHECK(vkCreateCommandPool(dev, &cpi, NULL, &cp));
    VkCommandBufferAllocateInfo cbai = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO, NULL, cp, VK_COMMAND_BUFFER_LEVEL_PRIMARY, 1};
    VkCommandBuffer cb;
    CHECK(vkAllocateCommandBuffers(dev, &cbai, &cb));
    VkCommandBufferBeginInfo cbbi = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO, NULL, VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT, NULL};
    CHECK(vkBeginCommandBuffer(cb, &cbbi));
    vkCmdBindPipeline(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pipe);
    vkCmdBindDescriptorSets(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pl, 0, 1, &ds, 0, NULL);
    vkCmdDispatch(cb, N / 64, 1, 1);
    VkMemoryBarrier mb = {VK_STRUCTURE_TYPE_MEMORY_BARRIER, NULL, VK_ACCESS_SHADER_WRITE_BIT, VK_ACCESS_HOST_READ_BIT};
    vkCmdPipelineBarrier(cb, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_HOST_BIT, 0, 1, &mb, 0, NULL, 0, NULL);
    CHECK(vkEndCommandBuffer(cb));
    VkFenceCreateInfo fci = {VK_STRUCTURE_TYPE_FENCE_CREATE_INFO, NULL, 0};
    VkFence fence;
    CHECK(vkCreateFence(dev, &fci, NULL, &fence));
    VkSubmitInfo si = {VK_STRUCTURE_TYPE_SUBMIT_INFO, NULL, 0, NULL, NULL, 1, &cb, 0, NULL};
    CHECK(vkQueueSubmit(queue, 1, &si, fence));
    CHECK(vkWaitForFences(dev, 1, &fence, VK_TRUE, 60ull * 1000000000ull));

    for (uint32_t i = 0; i < N; i++) {
        if (data[i] != 2 * i + 1) { printf("compute: wrong at %u: %u\n", i, data[i]); return 1; }
    }
    printf("compute: ok %d\n", N);
    vkDestroyFence(dev, fence, NULL);
    vkDestroyCommandPool(dev, cp, NULL);
    vkDestroyDescriptorPool(dev, dp, NULL);
    vkDestroyPipeline(dev, pipe, NULL);
    vkDestroyPipelineLayout(dev, pl, NULL);
    vkDestroyDescriptorSetLayout(dev, dsl, NULL);
    vkDestroyShaderModule(dev, sm, NULL);
    vkUnmapMemory(dev, mem);
    vkFreeMemory(dev, mem, NULL);
    vkDestroyBuffer(dev, buf, NULL);
    vkDestroyDevice(dev, NULL);
    vkDestroyInstance(inst, NULL);
    return 0;
}
