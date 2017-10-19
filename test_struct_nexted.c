
struct mtype {
	int a;
};

struct fff {
	struct test {
		int m2;
		struct zzz {
			int fu1;
		} m3;
		typedef struct mtype z;
		z m5;
	};
};

