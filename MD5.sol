

contract MD5 {

    event Debug(uint256 g, uint32 index);
    event DebugRound(uint32 a, uint32 b, uint32 c, uint32 d);

    uint32[] s =  [
                                7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
                                5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
                                4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
                                6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
                            ];
    uint32[64] K = [
                               0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                                0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                                0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                                0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                                0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                                0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                                0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                                0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                                0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                                0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                                0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                                0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                                0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                                0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                                0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                                0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
                            ];

    function digest(bytes in_data) returns (bytes1[16]) {
        uint32 a0 = 0x67452301;   //A
        uint32 b0 = 0xefcdab89;   //B
        uint32 c0 = 0x98badcfe;   //C
        uint32 d0 = 0x10325476;   //D
        
        uint256 length = (in_data.length * 8) % (2 ** 64);

        bytes memory data = new bytes(((in_data.length-1) / 64) * 64 + 64); 
        uint256 i;
        for(i = 0; i < in_data.length; ++i) {
            data[i] = in_data[i];
        }
        
        data[in_data.length] = byte(128);
        /*for(i = in_data.length+1; i < data.length-8; ++i) {
            data[i] = 0;
        }*/
        for(i = 0; i < 8; ++i) {
            data[data.length - (8-i)] = (byte((length / (2 ** ((i)*8))) % 0xff));
        }

        for(i = 0; i < data.length; i += 64) {
            (a0, b0, c0, d0) = do_round(data, i, a0, b0, c0, d0);
        }

        bytes1[16] memory digest = [
                            byte(((a0 / (2**0)) % 256)), byte(((a0 / (2**8)) % 256)), byte(((a0 / (2**16)) % 256)), byte(((d0 / (2**24)) % 256)), 
                            byte(((b0 / (2**0)) % 256)), byte(((b0 / (2**8)) % 256)), byte(((b0 / (2**16)) % 256)), byte(((d0 / (2**24)) % 256)), 
                            byte(((c0 / (2**0)) % 256)), byte(((c0 / (2**8)) % 256)), byte(((c0 / (2**16)) % 256)), byte(((d0 / (2**24)) % 256)), 
                            byte(((d0 / (2**0)) % 256)), byte(((d0 / (2**8)) % 256)), byte(((d0 / (2**16)) % 256)), byte(((d0 / (2**24)) % 256))
                        ];
        return digest;
    }

    function do_round(bytes data, uint256 i, uint32 a0, uint32 b0, uint32 c0, uint32 d0) returns (uint32, uint32, uint32, uint32) {
            uint32[4] memory v = [a0, b0, c0, d0];
            for(uint32 j = 0; j < 64; ++j) {
                v = do_sub_round(data, i, j, v[0], v[1], v[2], v[3]);
                DebugRound(v[0], v[1], v[2], v[3]);
            }
            return (a0 + v[0], b0 + v[1], c0 + v[2], d0 + v[3]);
    }
    
    function do_sub_round(bytes data, uint256 i, uint32 j, uint32 A, uint32 B, uint32 C, uint32 D) returns (uint32[4]) {
        uint32 F;
        uint32 g;
        if(0 <= j && j <= 15) {
            F = (B & C) | ((~B) & D);
            g = j;
        } else if (16 <= j && j <= 31) {
            F = (D & B) | ((~D) & C);
            g = (5 * j + 1) % 16;
        } else if (32 <= j && j <= 47) {
            F = B ^ C ^ D;
            g = (3*j+5) % 16;
        } else if (48 <= j && j <= 63) {
            F = C ^ (B | (~D));
            g = (7*j) % 16;
        }
        uint32 M = do_get_sub_round_seed(data, i, g*4);
        Debug(g, M);
        return [D, B + left_rotate(A + F + K[j] +  M, s[j]), B, C];
    }

    function do_get_sub_round_seed(bytes data, uint256 i, uint32 g) returns (uint32) {
        return (uint32(data[i+g])) + (uint32(data[i+g+1])*(2**8)) + (uint32(data[i+g+2])*(2**16)) + (uint32(data[i+g+3])*(2**24)); 
    }

    function left_rotate(uint32 x, uint32 c) returns (uint32) {
        return (x * (2**c)) | (x / (2**(32-c)));
    }
}
