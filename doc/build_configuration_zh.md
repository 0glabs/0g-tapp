# TDX TAPP构建指南

## 构建方式概述

TDX TAPP项目提供两种构建方式：
1. **自动化构建**：使用 `build.sh` 脚本（推荐）
2. **手动构建**：使用CMake命令

## 方式一：自动化构建（推荐）

### 脚本语法
```bash
./build.sh [选项] [目标]
```

### 选项参数
```bash
--build-type TYPE         # 构建类型: Release|Debug (默认Release)
--install-prefix DIR      # 安装路径 (默认/usr/local)
--enable-testing         # 启用测试
--disable-testing        # 禁用测试 (默认)
--force-tdx             # 强制启用TDX支持
--grpc-version VER      # gRPC版本 (默认v1.50.0)
--help                  # 显示帮助
```

### 构建目标
```bash
deps                    # 安装系统依赖
grpc                   # 编译安装gRPC
tdx-check              # 检查TDX支持
configure              # 配置构建
build                  # 编译项目
test                   # 运行测试
format                 # 格式化代码
install                # 安装到系统
examples               # 运行示例
package                # 创建安装包
all                    # 执行完整构建 (默认)
clean                  # 清理构建目录
```

### 常用命令
```bash
# 完整自动化构建
./build.sh

# 只编译gRPC
./build.sh grpc

# Debug构建
./build.sh --build-type Debug configure build

# 启用测试
./build.sh --enable-testing build test

# 强制TDX支持
./build.sh --force-tdx configure build

# 检查TDX支持
./build.sh tdx-check

# 清理重建
./build.sh clean configure build

# 自定义安装路径
./build.sh --install-prefix /opt/tdx install
```

## 方式二：手动CMake构建

### 系统依赖安装

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential cmake pkg-config libssl-dev \
    libprotobuf-dev protobuf-compiler \
    autoconf libtool zlib1g-dev
```

#### CentOS/RHEL
```bash
sudo yum groupinstall -y "Development Tools"
sudo yum install -y \
    cmake pkgconfig openssl-devel \
    protobuf-devel protobuf-compiler \
    autoconf libtool zlib-devel
```

### gRPC源码编译
```bash
# 克隆gRPC源码
git clone --recurse-submodules -b v1.50.0 \
    https://github.com/grpc/grpc
cd grpc && mkdir build && cd build

# 配置和编译
cmake -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF ..
make -j4 && sudo make install

# 更新库缓存 (Linux)
sudo ldconfig
```

### CMake构建参数

#### 基本参数
```bash
cmake -DCMAKE_BUILD_TYPE=Release ..        # 构建类型：Release/Debug
cmake -DCMAKE_INSTALL_PREFIX=/usr/local .. # 安装路径
cmake -DCMAKE_C_COMPILER=gcc ..            # C编译器
cmake -DCMAKE_CXX_COMPILER=g++ ..          # C++编译器
```

#### 项目参数
```bash
cmake -DFORCE_TDX_SUPPORT=ON ..     # 强制启用TDX支持（默认OFF）
cmake -DBUILD_TESTING=ON ..         # 启用测试构建（默认OFF）
cmake -DTDX_DEPS_DIR=/path/to/deps  # TDX依赖源码目录（默认./deps）
```

### 构建目标

#### 主要目标
```bash
make                    # 构建所有目标
make tapp_cli          # CLI可执行文件
make tapp_server       # gRPC服务器
make tapp_tests        # 测试程序（需要BUILD_TESTING=ON）
```

#### 库目标
```bash
make boost_lib          # Boost功能库
make key_tool_lib       # 密钥工具库
make tapp_proto         # Protocol Buffers生成代码
make tdx_attest_local   # 本地TDX认证库（如果使用本地源码）
```

#### 实用目标
```bash
make format            # 代码格式化（需要clang-format）
make clean-all         # 清理所有构建文件
make check-tdx         # 检查TDX硬件支持
make install           # 安装到系统
make test              # 运行测试
```

### 手动构建示例

#### 标准构建
```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

#### 调试构建
```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

#### 带测试的构建
```bash
mkdir build && cd build
cmake -DBUILD_TESTING=ON ..
make -j$(nproc)
make test
```

#### 强制TDX支持构建
```bash
mkdir build && cd build
cmake -DFORCE_TDX_SUPPORT=ON ..
make -j$(nproc)
```

#### 自定义安装路径
```bash
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/opt/tdx_tapp ..
make -j$(nproc)
sudo make install
```

## TDX支持状态

构建时会显示以下状态之一：
- `TDX Support: ENABLED (System Library)` - 使用系统TDX库
- `TDX Support: ENABLED (Local Implementation)` - 使用deps/目录源码
- `TDX Support: DISABLED (No hardware support)` - 无硬件支持
- `TDX Support: DISABLED (No library/sources)` - 无库或源码

## 依赖检查

项目会自动检测以下依赖：
- CMake 3.16+
- C++17兼容编译器
- OpenSSL
- Protocol Buffers
- gRPC
- TDX硬件支持（通过多种方式检测）
- TDX认证库（系统库或deps/源码）