#include <stdint.h>

struct Base_c { void *unused; };
struct Base_Fields {
    int32_t a;
};
struct Base_o {
    struct Base_c *klass;
    void *monitor;
    struct Base_Fields fields;
};

struct Vec2_Fields {
    float x;
    float y;
};
struct Vec2_o {
    struct Vec2_Fields fields;
};

struct Derived_c { void *unused; };
struct Derived_Fields : Base_Fields {
    struct Vec2_o position;
    int32_t values[3];
    int32_t overlapA;
    float overlapB;
    int64_t wide;
    int32_t tail;
    int32_t a;
};
struct Derived_o {
    struct Derived_c *klass;
    void *monitor;
    struct Derived_Fields fields;
};
