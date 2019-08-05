pragma solidity ^0.5.0;

import "LibSubmarineSimple.sol";

contract LibSubmarineSimpleTestHelper is LibSubmarineSimple {
	function onSubmarineReveal(
        bytes32 _submarineId,
        bytes memory _embeddedDAppData,
        uint256 _value
    ) internal {

    }
}
