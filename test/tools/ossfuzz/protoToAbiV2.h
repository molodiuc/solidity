#pragma once

#include <ostream>
#include <sstream>
#include <test/tools/ossfuzz/abiV2Proto.pb.h>
#include <libdevcore/Whiskers.h>
#include <libdevcore/FixedHash.h>

namespace dev
{
namespace test
{
namespace abiv2fuzzer
{
class ProtoConverter
{
public:
	ProtoConverter()
	{
		m_isStateVar = true;
		m_counter = 0;
		m_returnValue = 1;
	}
	ProtoConverter(ProtoConverter const&) = delete;
	ProtoConverter(ProtoConverter&&) = delete;
	std::string contractToString(Contract const& _input);

private:
	typedef std::tuple<std::string, bool, std::string> tupleOfStrBoolStrTy;
	typedef std::tuple<std::string, bool, std::vector<unsigned>> tupleOfStrBoolUnsignedVecTy;
	typedef std::vector<std::pair<bool,unsigned>> vecOfBoolUnsignedTy;

	enum class delimiter
	{
		ADD,
		SKIP
	};
	enum class calleeType
	{
		PUBLIC,
		EXTERNAL
	};
	enum class dataType
	{
		BYTES,
		STRING,
		VALUE
	};

	void visit(IntegerType const&);
	void visit(FixedByteType const&);
	void visit(AddressType const&);
	void visit(ArrayType const&);
	void visit(ArrayDimensionInfo const&);
	void initArray(std::string, ArrayType const&);
	void visit(DynamicByteArrayType const&);
	void visit(StructType const&);
	void visit(ValueType const&);
	void visit(NonValueType const&);
	void visit(Type const&);
	void visit(VarDecl const&);
	void visit(TestFunction const&);
	void visit(Contract const&);
	std::string getValueByBaseType(ArrayType const&);
	void resizeArray(std::string _expr, unsigned _length, std::string _type = {});

	// Utility
	void appendChecks(dataType _type, std::string const& _varName, std::string const& _rhs);
	void addCheckedVarDef(dataType _type, std::string const& _varName, std::string const& _rhs);
	void appendTypedParams(
			calleeType _calleeType,
			bool _isValueType,
			std::string const& _typeString,
			std::string const& _varName,
			delimiter _delimiter
	);
	void appendTypedParamsPublic(
			bool _isValueType,
			std::string const& _typeString,
			std::string const& _varName,
			delimiter _delimiter = delimiter::ADD
	);
	void appendTypedParamsExternal(
			bool _isValueType,
			std::string const& _typeString,
			std::string const& _varName,
			delimiter _delimiter = delimiter::ADD
	);
	void addCheckedResizeOp(std::string const& _expr, unsigned _length, std::string const& _type);
	void visitType(dataType _dataType, std::string const& _type, std::string const& _value);
	void appendVarDefToOutput(std::string const& _varName, std::string const& _rhs);
	std::string equalityChecksAsString();
	std::string typedParametersAsString(calleeType _calleeType);
	void writeHelperFunctions();
	void bufferVarDef(std::string const& _varName, std::string const& _rhs);

	// Inline functions
	inline unsigned getCounter()
	{
		return m_counter;
	}

	inline void incrementCounter()
	{
		m_counter++;
	}

	inline std::string newVarName()
	{
		return  ("x_" + std::to_string(m_counter));
	}

	inline std::string bytesArrayValueAsString()
	{
		return ("\"" + u256(h256(std::to_string(getCounter()))).str() + "\"");
	}

	inline std::string getQualifier(dataType _dataType)
	{
		return (!(isValueType(_dataType) || m_isStateVar) ? "memory" : "");
	}

	// Static declarations
	static std::string structTypeAsString(StructType const& _x);
	static std::string intValueAsString(unsigned _width, unsigned _counter);
	static std::string uintValueAsString(unsigned _width, unsigned _counter);
	static std::string integerValueAsString(bool _sign, unsigned _width, unsigned _counter);
	static std::string addressValueAsString(unsigned _counter);
	static std::string fixedByteValueAsString(unsigned _width, unsigned _counter);
	static std::vector<std::pair<bool, unsigned>> arrayDimensionsAsPairVector(ArrayType const& _x);
	static std::string arrayDimInfoAsString(ArrayDimensionInfo const& _x);
	static std::vector<std::string> arrayDimensionsAsStringVector(ArrayType const& _x);
	static std::string bytesArrayTypeAsString(DynamicByteArrayType const& _x);
	static std::pair<std::string,std::string> arrayTypeAsString(ArrayType const& _x, bool);

	// Static inline functions
	static inline bool isValueType(dataType _dataType)
	{
		return (_dataType == dataType::VALUE);
	}

	static inline std::string delimiterToString(delimiter _delimiter)
	{
		switch (_delimiter)
		{
		case delimiter::ADD:
			return ", ";
		case delimiter::SKIP:
			return "";
		}
	}

	static inline unsigned getIntWidth(IntegerType const& _x)
	{
		return (8 * ((_x.width() % 32) + 1));
	}

	static inline bool isIntSigned(IntegerType const& _x)
	{
		return _x.is_signed();
	}

	static inline std::string getIntTypeAsString(IntegerType const& _x)
	{
		return ((isIntSigned(_x) ? "int" : "uint") + std::to_string(getIntWidth(_x)));
	}

	static inline unsigned getFixedByteWidth(FixedByteType const& _x)
	{
		return ((_x.width() % 32) + 1);
	}

	static inline std::string getFixedByteTypeAsString(FixedByteType const& _x)
	{
		return ("bytes" + std::to_string(getFixedByteWidth(_x)));
	}

	static inline std::string getAddressTypeAsString(AddressType const& _x)
	{
		return (_x.payable() ? "address payable": "address");
	}

	static inline u256 hashUnsignedInt(unsigned _counter)
	{
		return u256(h256(std::to_string(_counter), h256::FromBinary, h256::AlignLeft));
	}

	static inline u256 maskUnsignedInt(unsigned _counter, unsigned _numMaskOctets)
	{
		return hashUnsignedInt(_counter) & u256("0x" + std::string(_numMaskOctets, 'f'));
	}

	static inline std::string maskUnsignedIntToHex(unsigned _counter, unsigned _numMaskOctets)
	{
		return toHex(maskUnsignedInt(_counter, _numMaskOctets), HexPrefix::Add);
	}

	static inline unsigned getArrayLengthFromFuzz(unsigned _fuzz, unsigned _counter = 0)
	{
		return (((_fuzz + _counter) % s_maxArrayLength) + 1);
	}

	static inline unsigned getArrayDimsFromFuzz(unsigned _fuzz)
	{
		return ((_fuzz % s_maxArrayDimensions) + 1);
	}

	static inline std::pair<bool, unsigned> arrayDimInfoAsPair(ArrayDimensionInfo const& _x)
	{
		return std::make_pair(_x.is_static(), getArrayLengthFromFuzz(_x.length()));
	}

	static inline std::string getResizeOpAsString(std::string const& _typeString, unsigned _length)
	{
		return Whiskers(R"(new <type>(<length>))")
				("type", _typeString)
				("length", std::to_string(_length))
				.render();
	}

	void appendVarDeclToOutput(
		std::string const& _type,
		std::string const& _varName,
		std::string const& _qualifier
	);

	template <typename T>
	bool isDynamicMemoryArray(T const& _x) const
	{
		return _x.has_array_info() && !m_isStateVar && !_x.array_info().is_static();
	}

	// Contains the test program
	std::ostringstream m_output;
	// Temporary storage for state variable definitions
	std::ostringstream m_statebuffer;
	// Contains a subset of the test program. This subset contains
	// checks to be encoded in the test program
	std::ostringstream m_checks;
	// Contains a subset of the test program. This subset contains
	// typed parameter list to be passed to callee functions.
	std::ostringstream m_typedParamsExternal;
	std::ostringstream m_typedParamsPublic;
	// Return value in case of error.
	unsigned m_returnValue;
	// Predicate that is true if we are in contract scope
	bool m_isStateVar;
	unsigned m_counter;
	static unsigned constexpr s_maxArrayLength = 3;
	static unsigned constexpr s_maxArrayDimensions = 4;
};
}
}
}