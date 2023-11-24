project(lib${ROOT_PROJECT_NAME})

# !!! TARGET-SPECIFIC !!! #

# Enlist source from current directory recursively
file(GLOB_RECURSE sources *.c *.cc *.cpp *.cxx)

# Add target library to build with source
add_library(${PROJECT_NAME} OBJECT ${sources})
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  add_library(${PROJECT_NAME}.lto OBJECT ${sources})
else()
  add_library(${PROJECT_NAME}.dbg OBJECT ${sources})
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

# Add directory for including headers
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  target_include_directories(${PROJECT_NAME}.lto
                             PUBLIC ${CMAKE_SOURCE_DIR}/include)
else()
  target_include_directories(${PROJECT_NAME}.dbg
                             PUBLIC ${CMAKE_SOURCE_DIR}/include)
endif()

# Add target library to build with source
add_library(${PROJECT_NAME}_static STATIC)
target_link_libraries(${PROJECT_NAME}_static PUBLIC ${PROJECT_NAME})
add_library(${PROJECT_NAME}_shared SHARED)
target_link_libraries(${PROJECT_NAME}_shared PUBLIC ${PROJECT_NAME})
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  add_library(${PROJECT_NAME}.lto_static STATIC)
  target_link_libraries(${PROJECT_NAME}.lto_static PUBLIC ${PROJECT_NAME})
  add_library(${PROJECT_NAME}.lto_shared SHARED)
  target_link_libraries(${PROJECT_NAME}.lto_shared PUBLIC ${PROJECT_NAME})
else()
  add_library(${PROJECT_NAME}.dbg_static STATIC)
  target_link_libraries(${PROJECT_NAME}.dbg_static PUBLIC ${PROJECT_NAME})
  add_library(${PROJECT_NAME}.dbg_shared SHARED)
  target_link_libraries(${PROJECT_NAME}.dbg_shared PUBLIC ${PROJECT_NAME})
endif()

# Add build options
target_compile_options(${PROJECT_NAME}
                       PUBLIC $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_NORM} -fpic>)
target_compile_options(
  ${PROJECT_NAME} PUBLIC $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_NORM} -fpic>)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  target_compile_options(${PROJECT_NAME}.lto
                         PUBLIC $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_LTO} -fpic>)
  target_compile_options(
    ${PROJECT_NAME}.lto PUBLIC $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_LTO}
                               -fpic>)

  # Set link option to strip out all debug & symbol information.
  target_link_options(${PROJECT_NAME}_static PUBLIC
                      $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_NORM} -s>)
  target_link_options(${PROJECT_NAME}_static PUBLIC
                      $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_NORM} -s>)
  target_link_options(${PROJECT_NAME}_shared PUBLIC
                      $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_NORM} -s>)
  target_link_options(${PROJECT_NAME}_shared PUBLIC
                      $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_NORM} -s>)
  target_link_options(${PROJECT_NAME}.lto_static PUBLIC
                      $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_LTO} -s>)
  target_link_options(${PROJECT_NAME}.lto_static PUBLIC
                      $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_LTO} -s>)
  target_link_options(${PROJECT_NAME}.lto_shared PUBLIC
                      $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_LTO} -s>)
  target_link_options(${PROJECT_NAME}.lto_shared PUBLIC
                      $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_LTO} -s>)
else()
  target_compile_options(${PROJECT_NAME}.dbg
                         PUBLIC $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_DBG} -fpic>)
  target_compile_options(
    ${PROJECT_NAME}.dbg PUBLIC $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_DBG}
                               -fpic>)

  # Set link option to maintain all debug & symbol information.
  target_link_options(${PROJECT_NAME}_static PUBLIC
                      $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_NORM} -rdynamic>)
  target_link_options(${PROJECT_NAME}_static PUBLIC
                      $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_NORM} -rdynamic>)
  target_link_options(${PROJECT_NAME}_shared PUBLIC
                      $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_NORM} -rdynamic>)
  target_link_options(${PROJECT_NAME}_shared PUBLIC
                      $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_NORM} -rdynamic>)
  target_link_options(${PROJECT_NAME}.dbg_static PUBLIC
                      $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_DBG} -rdynamic>)
  target_link_options(${PROJECT_NAME}.dbg_static PUBLIC
                      $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_DBG} -rdynamic>)
  target_link_options(${PROJECT_NAME}.dbg_shared PUBLIC
                      $<$<COMPILE_LANGUAGE:C>:${C_FLAGS_DBG} -rdynamic>)
  target_link_options(${PROJECT_NAME}.dbg_shared PUBLIC
                      $<$<COMPILE_LANGUAGE:CXX>:${CXX_FLAGS_DBG} -rdynamic>)
endif()

# Enforce output name format
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "")
set_target_properties(${PROJECT_NAME}_static PROPERTIES PREFIX "")
set_target_properties(${PROJECT_NAME}_shared PROPERTIES PREFIX "")
set_target_properties(${PROJECT_NAME}_static PROPERTIES OUTPUT_NAME
                                                        ${PROJECT_NAME})
set_target_properties(${PROJECT_NAME}_shared PROPERTIES OUTPUT_NAME
                                                        ${PROJECT_NAME})
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set_target_properties(${PROJECT_NAME}.lto PROPERTIES PREFIX "")
  set_target_properties(${PROJECT_NAME}.lto_static PROPERTIES PREFIX "")
  set_target_properties(${PROJECT_NAME}.lto_shared PROPERTIES PREFIX "")
  set_target_properties(${PROJECT_NAME}.lto_static
                        PROPERTIES OUTPUT_NAME ${PROJECT_NAME}.lto)
  set_target_properties(${PROJECT_NAME}.lto_shared
                        PROPERTIES OUTPUT_NAME ${PROJECT_NAME}.lto)
else()
  set_target_properties(${PROJECT_NAME}.dbg PROPERTIES PREFIX "")
  set_target_properties(${PROJECT_NAME}.dbg_static PROPERTIES PREFIX "")
  set_target_properties(${PROJECT_NAME}.dbg_shared PROPERTIES PREFIX "")
  set_target_properties(${PROJECT_NAME}.dbg_static
                        PROPERTIES OUTPUT_NAME ${PROJECT_NAME}.dbg)
  set_target_properties(${PROJECT_NAME}.dbg_shared
                        PROPERTIES OUTPUT_NAME ${PROJECT_NAME}.dbg)
endif()

# Set custom directory for "install"
install(TARGETS ${PROJECT_NAME}_static LIBRARY DESTINATION ${INSTALL_LIB_DIR})
install(TARGETS ${PROJECT_NAME}_shared LIBRARY DESTINATION ${INSTALL_LIB_DIR})
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  install(TARGETS ${PROJECT_NAME}.lto_static
          LIBRARY DESTINATION ${INSTALL_LIB_DIR})
  install(TARGETS ${PROJECT_NAME}.lto_shared
          LIBRARY DESTINATION ${INSTALL_LIB_DIR})
else()
  install(TARGETS ${PROJECT_NAME}.dbg_static
          LIBRARY DESTINATION ${INSTALL_LIB_DIR})
  install(TARGETS ${PROJECT_NAME}.dbg_shared
          LIBRARY DESTINATION ${INSTALL_LIB_DIR})
endif()
