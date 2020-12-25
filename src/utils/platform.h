#include <stddef.h>
#include <errno.h>
#if defined(__APPLE__)
#include <machine/endian.h>
#else
#include <endian.h>
#endif

#define le16_to_cpu		le16toh
#define le32_to_cpu		le32toh

#define get_unaligned_uint16(p)					\
({							\
	struct packed_dummy_struct {				\
		uint16_t __val;				\
	} __attribute__((packed)) *__ptr = (void *) (p);	\
								\
	__ptr->__val;						\
})
#define get_unaligned_uint32(p)					\
({							\
	struct packed_dummy_struct {				\
		uint32_t __val;				\
	} __attribute__((packed)) *__ptr = (void *) (p);	\
								\
	__ptr->__val;						\
})
#define get_unaligned_le16(p)	le16_to_cpu(get_unaligned_uint16((uint16_t *)(p)))
#define get_unaligned_le32(p)	le32_to_cpu(get_unaligned_uint32((uint32_t *)(p)))

//#define get_unaligned_le16(p)	le16_to_cpu(get_unaligned((uint16_t *)(p)))
//#define get_unaligned_le32(p)	le32_to_cpu(get_unaligned((uint32_t *)(p)))
