pragma solidity ^0.4.24;

library SafeMath32 {

    function mul(uint32 a, uint32 b) internal pure returns (uint32 c) {
        if (a == 0)
            return 0;
        c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint32 a, uint32 b) internal pure returns (uint32) {
        return a / b;
    }

    function sub(uint32 a, uint32 b) internal pure returns (uint32) {
        assert(b <= a);
        return a - b;
    }

    function add(uint32 a, uint32 b) internal pure returns (uint32 c) {
        c = a + b;
        assert(c >= a);
        return c;
    }
}
