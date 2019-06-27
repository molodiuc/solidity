contract C {
	function index(uint256 len) public returns (bool)
	{
		uint[] memory array = new uint[](len);

		for (uint256 i = 0; i < len; i++)
			array[i] = i + 1;

		for (uint256 i = 0; i < len; i++)
			require(array[i] == i + 1, "Unexpected value in array!");

		return array.length == len;
	}
}
// ====
// compileViaYul: true
// ----
// index(uint256): 0 -> true
// index(uint256): 10 -> true
// index(uint256): 20 -> true
// index(uint256): 0xFF -> true
