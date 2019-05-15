#include <regex>
#include <numeric>
#include <boost/range/adaptor/reversed.hpp>
#include <test/tools/ossfuzz/protoToAbiV2.h>
#include <libsolidity/codegen/YulUtilFunctions.h>
#include <libdevcore/Whiskers.h>
#include <liblangutil/Exceptions.h>

using namespace std;
using namespace dev::solidity;
using namespace dev::test::abiv2fuzzer;

void ProtoConverter::visitType(
	dataType _dataType,
	std::string const& _type,
	std::string const& _value
)
{
	std::string varName = newVarName();
	appendVarDeclToOutput(_type, varName, getQualifier(_dataType));
	appendTypedParams(
		calleeType::PUBLIC,
		isValueType(_dataType),
		_type,
		varName,
		((m_counter == 0) ? delimiter::SKIP : delimiter::ADD)
	);
	appendTypedParams(
		calleeType::EXTERNAL,
		isValueType(_dataType),
		_type,
		varName,
		((m_counter == 0) ? delimiter::SKIP : delimiter::ADD)
	);
	addCheckedVarDef(_dataType, varName, _value);
	incrementCounter();
}

void ProtoConverter::appendVarDeclToOutput(
	std::string const& _type,
	std::string const& _varName,
	std::string const& _qualifier
)
{
	m_output << Whiskers(R"(
	<type><?qual> <qualifier></qual> <varName>;)"
	)
		("type", _type)
		("qual", !_qualifier.empty())
		("qualifier", _qualifier)
		("varName", _varName)
		.render();
}

void ProtoConverter::bufferVarDef(std::string const& _varName, std::string const& _rhs)
{
	m_statebuffer << Whiskers(R"(
		<varName> = <rhs>;)"
	)
		("varName", _varName)
		("rhs", _rhs)
		.render();
}

void ProtoConverter::appendVarDefToOutput(std::string const& _varName, std::string const& _rhs)
{
	m_output << Whiskers(R"(
	<varName> = <rhs>;)"
	)
		("varName", _varName)
		("rhs", _rhs)
		.render();
}

void ProtoConverter::appendChecks(
	dataType _type,
	std::string const& _varName,
	std::string const& _rhs
)
{
	std::string check = {};
	switch (_type)
	{
	case dataType::STRING:
		check = Whiskers(R"(!stringCompare(<varName>, <value>))")
			("varName", _varName)
			("value", _rhs)
			.render();
		break;
	case dataType::BYTES:
		check = Whiskers(R"(!bytesCompare(<varName>, <value>))")
			("varName", _varName)
			("value", _rhs)
			.render();
		break;
	case dataType::VALUE:
		check = Whiskers(R"(<varName> != <value>)")
			("varName", _varName)
			("value", _rhs)
			.render();
		break;
	}

	m_checks << Whiskers(R"(
		if (<check>) return <returnVal>;)"
	)
		("check", check)
		("returnVal", std::to_string(m_returnValue++))
		.render();
}

void ProtoConverter::addCheckedVarDef(
	dataType _type,
	std::string const& _varName,
	std::string const& _rhs)
{
	// State variables cannot be assigned in contract-scope
	// Therefore, we buffer state variable assignments and
	// render them in function scope later.
	if (m_isStateVar)
		bufferVarDef(_varName, _rhs);
	else
		appendVarDefToOutput(_varName, _rhs);
	appendChecks(_type, _varName, _rhs);
}

/* Input(s)
 *   - Unsigned integer to be hashed
 *   - Width of desired uint value
 * Processing
 *   - Take hash of first parameter and mask it with the max unsigned value for given bit width
 * Output
 *   - string representation of uint value
 */
std::string ProtoConverter::uintValueAsString(unsigned _width, unsigned _counter)
{
	solAssert(
		(_width % 8 == 0),
		"Proto ABIv2 Fuzzer: Unsigned integer width is not a multiple of 8"
	);
	return maskUnsignedIntToHex(_counter, _width/4);
}

/* Input(s)
 *   - counter to be hashed to derive a value for Integer type
 *   - Width of desired int value
 * Processing
 *   - Take hash of first parameter and mask it with the max signed value for given bit width
 * Output
 *   - string representation of int value
 */
std::string ProtoConverter::intValueAsString(unsigned _width, unsigned _counter)
{
	solAssert(
		(_width % 8 == 0),
		"Proto ABIv2 Fuzzer: Signed integer width is not a multiple of 8"
	);
	return maskUnsignedIntToHex(_counter, ((_width/4) - 1));
}

std::string ProtoConverter::addressValueAsString(unsigned _counter)
{
	return Whiskers(R"(address(<value>))")
		("value", uintValueAsString(_counter, 160))
		.render();
}

std::string ProtoConverter::fixedByteValueAsString(unsigned _width, unsigned _counter)
{
	solAssert(
		(_width >= 1 && _width <= 32),
		"Proto ABIv2 Fuzzer: Fixed byte width is not between 1--32"
	);
	return maskUnsignedIntToHex(_counter, _width*2);
}

std::string ProtoConverter::integerValueAsString(bool _sign, unsigned _width, unsigned _counter)
{
	if (_sign)
		return intValueAsString(_width, _counter);
	else
		return uintValueAsString(_width, _counter);
}

std::string ProtoConverter::bytesArrayTypeAsString(DynamicByteArrayType const& _x)
{
	switch (_x.type())
	{
	case DynamicByteArrayType::BYTES:
		return "bytes";
	case DynamicByteArrayType::STRING:
		return "string";
	}
}

std::string ProtoConverter::structTypeAsString(StructType const&)
{
	// TODO: Implement this
	return {};
}

void ProtoConverter::visit(IntegerType const& _x)
{
	visitType(
		dataType::VALUE,
		getIntTypeAsString(_x),
		integerValueAsString(isIntSigned(_x), getIntWidth(_x), getCounter())
	);
}

void ProtoConverter::visit(AddressType const& _x)
{
	visitType(
		dataType::VALUE,
		getAddressTypeAsString(_x),
		addressValueAsString(getCounter())
	);
}

void ProtoConverter::visit(FixedByteType const& _x)
{
	visitType(
		dataType::VALUE,
		getFixedByteTypeAsString(_x),
		fixedByteValueAsString(getFixedByteWidth(_x), getCounter())
	);
}

void ProtoConverter::visit(ValueType const& _x)
{
	switch (_x.value_type_oneof_case())
	{
		case ValueType::kInty:
			visit(_x.inty());
			break;
		case ValueType::kByty:
			visit(_x.byty());
			break;
		case ValueType::kAdty:
			visit(_x.adty());
			break;
		case ValueType::VALUE_TYPE_ONEOF_NOT_SET:
			break;
	}
}

void ProtoConverter::visit(DynamicByteArrayType const& _x)
{
	visitType(
		(_x.type() == DynamicByteArrayType::BYTES) ? dataType::BYTES : dataType::STRING,
		bytesArrayTypeAsString(_x),
		bytesArrayValueAsString()
	);
}

// TODO: Implement struct visitor
void ProtoConverter::visit(StructType const&)
{
}

std::string ProtoConverter::arrayDimInfoAsString(ArrayDimensionInfo const& _x)
{
	unsigned arrLength = getArrayLengthFromFuzz(_x.length());
	if (_x.is_static())
		return Whiskers(R"([<length>])")
		("length", std::to_string(arrLength))
		.render();
	else
		return Whiskers(R"([])").render();
}

std::vector<std::string> ProtoConverter::arrayDimensionsAsStringVector(ArrayType const& _x)
{
	std::vector<std::string> arrayDimsStringVector = {};
	for (auto const& dim: _x.info())
		arrayDimsStringVector.push_back(arrayDimInfoAsString(dim));
	solAssert(!arrayDimsStringVector.empty(), "Proto ABIv2 Fuzzer: Array dimensions empty.");
	return arrayDimsStringVector;
}

ProtoConverter::vecOfBoolUnsignedTy ProtoConverter::arrayDimensionsAsPairVector(
	ArrayType const& _x
)
{
	vecOfBoolUnsignedTy arrayDimsPairVector = {};
	for (auto const& dim: _x.info())
		arrayDimsPairVector.push_back(arrayDimInfoAsPair(dim));
	solAssert(!arrayDimsPairVector.empty(), "Proto ABIv2 Fuzzer: Array dimensions empty.");
	return arrayDimsPairVector;
}

#if 0
void ProtoConverter::initArrayDimensions(ArrayType const& _x)
{
	// Start from outer most dimension
	for (auto const& b: boost::adaptors::reverse(arrayDimensionsAsPairVector(_x)))
		initArrayDimensions(_x);
}
#endif

std::string ProtoConverter::getValueByBaseType(ArrayType const& _x)
{
	switch (_x.base_type_oneof_case())
	{
	case ArrayType::kInty:
		return integerValueAsString(isIntSigned(_x.inty()), getIntWidth(_x.inty()), getCounter());
	case ArrayType::kByty:
		return fixedByteValueAsString(getFixedByteWidth(_x.byty()), getCounter());
	case ArrayType::kAdty:
		return addressValueAsString(getCounter());
	case ArrayType::kStty:
	case ArrayType::BASE_TYPE_ONEOF_NOT_SET:
		solAssert(false, "Proto ABIv2 fuzzer: Invalid array base type");
	}
}

#if 0
/* Name: initialize local array
 * Input:
 *   - arraydimensionsaspairvector
 * Processing:
 *   - reverse iterate vector
 *     - if dimension static, continue
 *     - else
 *       - append x([])+ =
 */
void ProtoConverter::resizeLocalArray(
	ArrayType const& _x,
	std::string _var,
	vecOfBoolUnsignedTy& _arrInfoVec,
	std::vector<std::string>& _arrStrVec
)
{
	// Start from outer most dimension
	for (auto const& b: boost::adaptors::reverse(_arrInfoVec))
	{
		// Skip past statically sized dimensions
		if (b.first)
		{
			// Remove statically sized element from vector
			_arrInfoVec.pop_back();
			for (unsigned i=0; i<b.second; i++)
				resizeLocalArray(_var + "[" + std::to_string(i) + "]", _arrInfoVec, _arrStrVec);
		}
		// x = new T(length);
		appendVarDefToOutput(_var, resize_op);



		/* Let size of this dimension be N
		 *
		 */
		unsigned length = b.second;
		for (unsigned i=0; i<length; i++)
		{
			// create assignment
		}



	}
	// No dimensions left to visit, so start assigning
	appendVarDefToOutput(_var, getValueByBaseType(_x));
	incrementCounter();
}

/* Name: initialize storage array
 * Input:
 *
 */
void ProtoConverter::resizeStorageArray()
{

}

// Declare array
// T x; // storage
// T memory x; // local
void ProtoConverter::initArray(std::string _baseType, ArrayType const& _x)
{
	std::vector<std::string> typeStringVec = {_baseType};
	std::vector<std::string> arrayDimStringVec = arrayDimensionsAsStringVector(_x);
	typeStringVec.insert(
		typeStringVec.end(),
		arrayDimStringVec.begin(),
		arrayDimStringVec.end()
	);

	// Qualified type = "base type" + "[(\d)?]+" + (" memory")?
	std::string qualifiedType =
		std::accumulate(typeStringVec.begin(), typeStringVec.end(), std::string("")) +
		(m_isStateVar ? "" : " memory");
	cout << qualifiedType << endl;
	appendVarDeclToOutput(qualifiedType);

	// This vector contains <flag,length> to be interpreted as isStatic, length of array
	// in dimension
	vecOfBoolUnsignedTy arrayVec = arrayDimensionsAsPairVector(_x);

	// Initialize array
	if (m_isStateVar)
		initStorageArray();
	else
		initLocalArray();
}
#endif

void ProtoConverter::visit(ArrayType const& _x)
{
	if (_x.info_size() == 0)
		return;

	string baseType = {};
	switch (_x.base_type_oneof_case())
	{
	case ArrayType::kInty:
		baseType = getIntTypeAsString(_x.inty());
		break;
	case ArrayType::kByty:
		baseType = getFixedByteTypeAsString(_x.byty());
		break;
	case ArrayType::kAdty:
		baseType = getAddressTypeAsString(_x.adty());
		break;
	case ArrayType::kStty:
	case ArrayType::BASE_TYPE_ONEOF_NOT_SET:
		return;
	}
	// TODO: Implement this
}

void ProtoConverter::visit(NonValueType const& _x)
{
	switch (_x.nonvalue_type_oneof_case())
	{
	case NonValueType::kDynbytearray:
		visit(_x.dynbytearray());
		break;
	case NonValueType::kArrtype:
		visit(_x.arrtype());
		break;
	case NonValueType::kStype:
		visit(_x.stype());
		break;
	case NonValueType::NONVALUE_TYPE_ONEOF_NOT_SET:
		break;
	}
}

void ProtoConverter::visit(Type const& _x)
{
	switch (_x.type_oneof_case())
	{
		case Type::kVtype:
			visit(_x.vtype());
			break;
		case Type::kNvtype:
			visit(_x.nvtype());
			break;
		case Type::TYPE_ONEOF_NOT_SET:
			break;
	}
}

void ProtoConverter::visit(VarDecl const& _x)
{
	visit(_x.type());
}

std::string ProtoConverter::equalityChecksAsString()
{
	return m_checks.str();
}

/* When a new variable is declared, we can invoke this function
 * to prepare the typed param list to be passed to callee functions.
 * We independently prepare this list for "public" and "external"
 * callee functions.
 */
void ProtoConverter::appendTypedParams(
	calleeType _calleeType,
	bool _isValueType,
	std::string const& _typeString,
	std::string const& _varName,
	delimiter _delimiter
)
{
	switch (_calleeType)
	{
	case calleeType::PUBLIC:
		appendTypedParamsPublic(_isValueType, _typeString, _varName, _delimiter);
		break;
	case calleeType::EXTERNAL:
		appendTypedParamsExternal(_isValueType, _typeString, _varName, _delimiter);
		break;
	}
}

void ProtoConverter::appendTypedParamsExternal(
	bool _isValueType,
    std::string const& _typeString,
    std::string const& _varName,
    delimiter _delimiter
)
{
	std::string qualifiedTypeString = (
		_isValueType ?
		_typeString :
		_typeString + " calldata"
		);
	m_typedParamsExternal << Whiskers(R"(<delimiter><type> <varName>)")
		("delimiter", delimiterToString(_delimiter))
		("type", qualifiedTypeString)
		("varName", _varName)
		.render();
}

/* Consider variable declaration of the form
 *  T x;
 * If T is a non-value type, then we need to suffix "memory"
 * to the type.
 */
void ProtoConverter::appendTypedParamsPublic(
	bool _isValueType,
	std::string const& _typeString,
	std::string const& _varName,
	delimiter _delimiter
)
{
	std::string qualifiedTypeString = (
		_isValueType ?
		_typeString :
		_typeString + " memory"
		);
	m_typedParamsPublic << Whiskers(R"(<delimiter><type> <varName>)")
		("delimiter", delimiterToString(_delimiter))
		("type", qualifiedTypeString)
		("varName", _varName)
		.render();
}

std::string ProtoConverter::typedParametersAsString(calleeType _calleeType)
{
	switch (_calleeType)
	{
	case calleeType::PUBLIC:
		return m_typedParamsPublic.str();
	case calleeType::EXTERNAL:
		return m_typedParamsExternal.str();
	}
}

// Function that is called by the factory contract
void ProtoConverter::visit(TestFunction const& _x)
{
	m_output << Whiskers(R"(
	function f() public returns (uint) {
	)")
	.render();

	// Define state variables
	m_output << m_statebuffer.str();

	// TODO: Support more than one but less than N local variables
	visit(_x.local_vars());

	m_output << Whiskers(R"(
		uint returnVal = this.g_public(<parameter_names>);
		if (returnVal != 0)
			return returnVal;
		return (uint(1000) + this.g_external(<parameter_names>));
	}
	)")
	("parameter_names", YulUtilFunctions::suffixedVariableNameList("x_", 0, m_counter))
	.render();
}

void ProtoConverter::writeHelperFunctions()
{
	m_output << Whiskers(R"(
	function stringCompare(string memory a, string memory b) internal pure returns (bool) {
		if(bytes(a).length != bytes(b).length)
			return false;
		else
			return keccak256(bytes(a)) == keccak256(bytes(b));
	}
	)").render();

	m_output << Whiskers(R"(
	function bytesCompare(bytes memory a, bytes memory b) internal pure returns (bool) {
		if(a.length != b.length)
			return false;
		for (uint i = 0; i < a.length; i++)
			if (a[i] != b[i])
				return false;
		return true;
	}
	)").render();

	// These are callee functions that encode from storage, decode to
	// memory/calldata and check if decoded value matches storage value
	// return true on successful match, false otherwise
	m_output << Whiskers(R"(
	function g_public(<parameters_memory>) public view returns (uint) {
		<equality_checks>
		return 0;
	}

	function g_external(<parameters_calldata>) external view returns (uint) {
		<equality_checks>
		return 0;
	}
	)")
		("parameters_memory", typedParametersAsString(calleeType::PUBLIC))
		("equality_checks", equalityChecksAsString())
		("parameters_calldata", typedParametersAsString(calleeType::EXTERNAL))
		.render();
}

void ProtoConverter::visit(Contract const& _x)
{
	m_output << Whiskers(R"(pragma solidity >=0.0;
pragma experimental ABIEncoderV2;

contract Factory {
	function test() external returns (uint) {
		C c = new C();
		return c.f();
	}
}

contract C {
)").render();
	// TODO: Support more than one but less than N state variables
	visit(_x.state_vars());
	m_isStateVar = false;
	// Test function
	visit(_x.testfunction());
	writeHelperFunctions();
	m_output << "\n}";
}

string ProtoConverter::contractToString(Contract const& _input)
{
	visit(_input);
	return m_output.str();
}