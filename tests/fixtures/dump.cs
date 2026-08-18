// Namespace:
public class Base
{
    public int a; // 0x10
}

// Namespace:
public struct Vec2
{
    public float x; // 0x0
    public float y; // 0x4
}

// Namespace:
public class Derived
{
    public Vec2 position; // 0x18
    public int[] values; // 0x20
    public int overlapA; // 0x2C
    public float overlapB; // 0x2C
    public long wide; // 0x30
    public int tail; // 0x34
    public int a; // 0x38
}
