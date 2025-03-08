set(OUTPUT_CONTENT "#include <stddef.h>\n")
foreach(INPUT_FILE ${INPUT_FILES})
	file(READ ${SOURCE_DIR}/${INPUT_FILE} INPUT_DATA_HEX HEX)
	string(SHA256 INPUT_HASH "${INPUT_DATA_HEX}")
	string(SUBSTRING "${INPUT_HASH}" 0 12 INPUT_HASH)
	
	string(REGEX REPLACE "[^a-zA-Z0-9_]" "_" OUTPUT_VAR ${INPUT_FILE})
	
	string(LENGTH ${INPUT_DATA_HEX} INPUT_DATA_LEN)
	math(EXPR INPUT_DATA_LEN "${INPUT_DATA_LEN} / 2")
	
	string(REGEX REPLACE "................" "\\0\n" INPUT_DATA_C_ARRAY "${INPUT_DATA_HEX}")
	string(REGEX REPLACE "[^\n][^\n]" "\\\\x\\0" INPUT_DATA_C_ARRAY "${INPUT_DATA_C_ARRAY}")
	string(REGEX REPLACE "\n" "\"\n\"" INPUT_DATA_C_ARRAY "${INPUT_DATA_C_ARRAY}")
	
	string(APPEND OUTPUT_CONTENT "\nstatic const char ${OUTPUT_VAR}[]=\n\"${INPUT_DATA_C_ARRAY}\\0\";\nstatic const size_t ${OUTPUT_VAR}_sz=${INPUT_DATA_LEN};\nstatic const char ${OUTPUT_VAR}_etag[] = \"\\\"${INPUT_HASH}\\\"\";\n")
	
endforeach()

file(WRITE ${OUTPUT_FILE} "${OUTPUT_CONTENT}")
