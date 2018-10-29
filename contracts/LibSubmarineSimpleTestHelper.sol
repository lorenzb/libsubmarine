pragma solidity ^0.4.24;

import "LibSubmarineSimple.sol";

contract LibSubmarineSimpleTestHelper is LibSubmarineSimple {
	function onSubmarineReveal(
        bytes32 _submarineId,
        bytes _embeddedDAppData,
        uint256 _value
    ) internal {

    }
}