# !!! TARGET-SPECIFIC !!! #

project(libintercept)

# Enlist source from current directory recursively
file(GLOB_RECURSE sources *.c *.cc *.cpp *.cxx)

# Add target library to build with source
add_library(${PROJECT_NAME} SHARED ${sources})
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  add_library(${PROJECT_NAME}.lto SHARED ${sources})
else()
  add_library(${PROJECT_NAME}.dbg SHARED ${sources})
endif()

# Find path of external library to link
find_library(item_libsyscall_intercept syscall_intercept)
find_library(item_libx86linuxextra x86linuxextra)
set(libraries ${item_libsyscall_intercept} ${item_libx86linuxextra})

# Add external library to link
target_link_libraries(${PROJECT_NAME} ${libraries})
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  target_link_libraries(${PROJECT_NAME}.lto ${libraries})
else()
  target_link_libraries(${PROJECT_NAME}.dbg ${libraries})
endif()

# DO NOT EDIT THE BELOW!

# Enforce output name format
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "")
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set_target_properties(${PROJECT_NAME}.lto PROPERTIES PREFIX "")
else()
  set_target_properties(${PROJECT_NAME}.dbg PROPERTIES PREFIX "")
endif()

# Add directory for including headers
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  target_include_directories(${PROJECT_NAME}.lto
                             PUBLIC ${CMAKE_SOURCE_DIR}/include)
else()
  target_include_directories(${PROJECT_NAME}.dbg
                             PUBLIC ${CMAKE_SOURCE_DIR}/include)
endif()

# Add build options
target_compile_options(${PROJECT_NAME}
                       PUBLIC $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_NORM}>)
target_compile_options(${PROJECT_NAME}
                       PUBLIC $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_NORM}>)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  target_compile_options(${PROJECT_NAME}.lto
                         PUBLIC $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_LTO}>)
  target_compile_options(${PROJECT_NAME}.lto
                         PUBLIC $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_LTO}>)

  # Set link option to strip out all debug & symbol information.
  target_link_options(${PROJECT_NAME} PUBLIC
                      $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_NORM} -Wl,-s>)
  target_link_options(${PROJECT_NAME} PUBLIC
                      $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_NORM} -Wl,-s>)
  target_link_options(${PROJECT_NAME}.lto PUBLIC
                      $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_LTO} -Wl,-s>)
  target_link_options(${PROJECT_NAME}.lto PUBLIC
                      $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_LTO} -Wl,-s>)
else()
  target_compile_options(${PROJECT_NAME}.dbg
                         PUBLIC $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_DBG}>)
  target_compile_options(${PROJECT_NAME}.dbg
                         PUBLIC $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_DBG}>)

  # Set link option to maintain all debug & symbol information.
  target_link_options(${PROJECT_NAME} PUBLIC
                      $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_NORM} -rdynamic>)
  target_link_options(${PROJECT_NAME} PUBLIC
                      $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_NORM} -rdynamic>)
  target_link_options(${PROJECT_NAME}.dbg PUBLIC
                      $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_DBG} -rdynamic>)
  target_link_options(${PROJECT_NAME}.dbg PUBLIC
                      $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_DBG} -rdynamic>)
endif()

# Set custom directory for "install"
install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION ${INSTALL_LIB_DIR})
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  install(TARGETS ${PROJECT_NAME}.lto LIBRARY DESTINATION ${INSTALL_LIB_DIR})
else()
  install(TARGETS ${PROJECT_NAME}.dbg LIBRARY DESTINATION ${INSTALL_LIB_DIR})
endif()
