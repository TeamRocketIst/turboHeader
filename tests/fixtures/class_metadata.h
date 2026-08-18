#include <stdint.h>

typedef uintptr_t il2cpp_array_size_t;

struct Il2CppObject {
    void *klass;
    void *monitor;
};

struct Il2CppArrayBounds {
    il2cpp_array_size_t length;
    int32_t lower_bound;
};

struct Fixture_Int32_array {
    struct Il2CppObject obj;
    struct Il2CppArrayBounds *bounds;
    il2cpp_array_size_t max_length;
    int32_t m_Items[65535];
};

struct LooksLikeArrayButIsNot {
    struct Il2CppObject obj;
    uint32_t count;
};

struct ExternalState;

struct VirtualInvokeData {
    void (*methodPtr)(void);
    void *method;
};

struct Il2CppClass;

struct Il2CppRuntimeInterfaceOffsetPair {
    struct Il2CppClass *interfaceType;
    int32_t offset;
};

struct Il2CppClass_1 {
    void *image;
    struct Il2CppRuntimeInterfaceOffsetPair *interfaceOffsets;
};

struct Il2CppClass_2 {
    uint8_t rank;
};

struct Cipher_VTable {
    struct VirtualInvokeData _0_Transform;
    struct VirtualInvokeData _1_Reset;
};

struct Cipher_StaticValue {
    uint32_t tag;
};

struct Cipher_Helper {
    int32_t value;
    struct Cipher_Helper *next;
};

struct Cipher_StaticFields {
    int32_t state;
    struct Cipher_StaticValue value;
    struct Cipher_Helper *helper;
    struct Fixture_Int32_array *offsets;
    struct LooksLikeArrayButIsNot *decoy;
    struct ExternalState *external;
    void *thread_cache;
};

struct Cipher_c {
    struct Il2CppClass_1 _1;
    struct Cipher_StaticFields *static_fields;
    void *rgctx_data;
    struct Il2CppClass_2 _2;
    struct Cipher_VTable vtable;
};

struct Cipher_Fields {
    int32_t keySize;
};

struct Cipher_o {
    struct Cipher_c *klass;
    void *monitor;
    struct Cipher_Fields fields;
};
