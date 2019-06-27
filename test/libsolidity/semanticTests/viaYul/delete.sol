contract C {
	function internal_func() internal pure returns (int8)
	{
		return 1;
	}
	function call_internal_func() public pure returns (bool ret)
	{
		function() internal pure returns(int8) func = internal_func;

		return func() == internal_func();
	}
	function call_deleted_internal_func() public pure returns (bool ret)
	{
		function() internal pure returns(int8) func = internal_func;

		delete func;

		return func() == internal_func();
	}
	function delete_memory_array() public returns (bool ret)
	{
		uint[] memory array = new uint[](7);

		for (uint i = 0; i < 7; i++)
			array[i] = i + 1;

		delete array;

		for (uint i = 0; i < 7; i++)
			require(array[i] == 0);

		return array.length == 7;
	}
}
// ====
// compileViaYul: true
// ----
// call_deleted_internal_func() -> FAILURE
// call_internal_func() -> true
// delete_memory_array() -> true
