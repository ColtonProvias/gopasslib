// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.21.12
// source: proto/gopasslib.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type PasswordArgon2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *PasswordArgon2) Reset() {
	*x = PasswordArgon2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_gopasslib_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PasswordArgon2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PasswordArgon2) ProtoMessage() {}

func (x *PasswordArgon2) ProtoReflect() protoreflect.Message {
	mi := &file_proto_gopasslib_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PasswordArgon2.ProtoReflect.Descriptor instead.
func (*PasswordArgon2) Descriptor() ([]byte, []int) {
	return file_proto_gopasslib_proto_rawDescGZIP(), []int{0}
}

type PasswordBcrypt struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *PasswordBcrypt) Reset() {
	*x = PasswordBcrypt{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_gopasslib_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PasswordBcrypt) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PasswordBcrypt) ProtoMessage() {}

func (x *PasswordBcrypt) ProtoReflect() protoreflect.Message {
	mi := &file_proto_gopasslib_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PasswordBcrypt.ProtoReflect.Descriptor instead.
func (*PasswordBcrypt) Descriptor() ([]byte, []int) {
	return file_proto_gopasslib_proto_rawDescGZIP(), []int{1}
}

type PasswordScrypt struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *PasswordScrypt) Reset() {
	*x = PasswordScrypt{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_gopasslib_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PasswordScrypt) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PasswordScrypt) ProtoMessage() {}

func (x *PasswordScrypt) ProtoReflect() protoreflect.Message {
	mi := &file_proto_gopasslib_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PasswordScrypt.ProtoReflect.Descriptor instead.
func (*PasswordScrypt) Descriptor() ([]byte, []int) {
	return file_proto_gopasslib_proto_rawDescGZIP(), []int{2}
}

type PasswordPBKDF2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *PasswordPBKDF2) Reset() {
	*x = PasswordPBKDF2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_gopasslib_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PasswordPBKDF2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PasswordPBKDF2) ProtoMessage() {}

func (x *PasswordPBKDF2) ProtoReflect() protoreflect.Message {
	mi := &file_proto_gopasslib_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PasswordPBKDF2.ProtoReflect.Descriptor instead.
func (*PasswordPBKDF2) Descriptor() ([]byte, []int) {
	return file_proto_gopasslib_proto_rawDescGZIP(), []int{3}
}

// PasswordContainer stores hashed passwords. All serialization/deserialization
// of passwords should use this rather than algorithm-specific messages. Doing
// as such helps for easier fallback to old algorithms when the default
// algorithm is changed.
type PasswordContainer struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to HashedPassword:
	//
	//	*PasswordContainer_Argon2
	//	*PasswordContainer_Bcrypt
	//	*PasswordContainer_Scrypt
	//	*PasswordContainer_Pbkdf2
	HashedPassword isPasswordContainer_HashedPassword `protobuf_oneof:"hashed_password"`
}

func (x *PasswordContainer) Reset() {
	*x = PasswordContainer{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_gopasslib_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PasswordContainer) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PasswordContainer) ProtoMessage() {}

func (x *PasswordContainer) ProtoReflect() protoreflect.Message {
	mi := &file_proto_gopasslib_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PasswordContainer.ProtoReflect.Descriptor instead.
func (*PasswordContainer) Descriptor() ([]byte, []int) {
	return file_proto_gopasslib_proto_rawDescGZIP(), []int{4}
}

func (m *PasswordContainer) GetHashedPassword() isPasswordContainer_HashedPassword {
	if m != nil {
		return m.HashedPassword
	}
	return nil
}

func (x *PasswordContainer) GetArgon2() *PasswordArgon2 {
	if x, ok := x.GetHashedPassword().(*PasswordContainer_Argon2); ok {
		return x.Argon2
	}
	return nil
}

func (x *PasswordContainer) GetBcrypt() *PasswordBcrypt {
	if x, ok := x.GetHashedPassword().(*PasswordContainer_Bcrypt); ok {
		return x.Bcrypt
	}
	return nil
}

func (x *PasswordContainer) GetScrypt() *PasswordScrypt {
	if x, ok := x.GetHashedPassword().(*PasswordContainer_Scrypt); ok {
		return x.Scrypt
	}
	return nil
}

func (x *PasswordContainer) GetPbkdf2() *PasswordPBKDF2 {
	if x, ok := x.GetHashedPassword().(*PasswordContainer_Pbkdf2); ok {
		return x.Pbkdf2
	}
	return nil
}

type isPasswordContainer_HashedPassword interface {
	isPasswordContainer_HashedPassword()
}

type PasswordContainer_Argon2 struct {
	Argon2 *PasswordArgon2 `protobuf:"bytes,1,opt,name=argon2,proto3,oneof"`
}

type PasswordContainer_Bcrypt struct {
	Bcrypt *PasswordBcrypt `protobuf:"bytes,2,opt,name=bcrypt,proto3,oneof"`
}

type PasswordContainer_Scrypt struct {
	Scrypt *PasswordScrypt `protobuf:"bytes,3,opt,name=scrypt,proto3,oneof"`
}

type PasswordContainer_Pbkdf2 struct {
	Pbkdf2 *PasswordPBKDF2 `protobuf:"bytes,4,opt,name=pbkdf2,proto3,oneof"`
}

func (*PasswordContainer_Argon2) isPasswordContainer_HashedPassword() {}

func (*PasswordContainer_Bcrypt) isPasswordContainer_HashedPassword() {}

func (*PasswordContainer_Scrypt) isPasswordContainer_HashedPassword() {}

func (*PasswordContainer_Pbkdf2) isPasswordContainer_HashedPassword() {}

var File_proto_gopasslib_proto protoreflect.FileDescriptor

var file_proto_gopasslib_proto_rawDesc = []byte{
	0x0a, 0x15, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x70, 0x61, 0x73, 0x73, 0x6c, 0x69,
	0x62, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x28, 0x63, 0x6f, 0x6d, 0x2e, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6c, 0x74, 0x6f, 0x6e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x61,
	0x73, 0x2e, 0x67, 0x6f, 0x70, 0x61, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0x10, 0x0a, 0x0e, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x41, 0x72, 0x67,
	0x6f, 0x6e, 0x32, 0x22, 0x10, 0x0a, 0x0e, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x42,
	0x63, 0x72, 0x79, 0x70, 0x74, 0x22, 0x10, 0x0a, 0x0e, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72,
	0x64, 0x53, 0x63, 0x72, 0x79, 0x70, 0x74, 0x22, 0x10, 0x0a, 0x0e, 0x50, 0x61, 0x73, 0x73, 0x77,
	0x6f, 0x72, 0x64, 0x50, 0x42, 0x4b, 0x44, 0x46, 0x32, 0x22, 0xf6, 0x02, 0x0a, 0x11, 0x50, 0x61,
	0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x12,
	0x52, 0x0a, 0x06, 0x61, 0x72, 0x67, 0x6f, 0x6e, 0x32, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x38, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6c,
	0x74, 0x6f, 0x6e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x61, 0x73, 0x2e, 0x67, 0x6f, 0x70, 0x61, 0x73,
	0x73, 0x6c, 0x69, 0x62, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x61, 0x73, 0x73, 0x77,
	0x6f, 0x72, 0x64, 0x41, 0x72, 0x67, 0x6f, 0x6e, 0x32, 0x48, 0x00, 0x52, 0x06, 0x61, 0x72, 0x67,
	0x6f, 0x6e, 0x32, 0x12, 0x52, 0x0a, 0x06, 0x62, 0x63, 0x72, 0x79, 0x70, 0x74, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x38, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6c, 0x74, 0x6f, 0x6e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x61, 0x73, 0x2e, 0x67,
	0x6f, 0x70, 0x61, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50,
	0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x42, 0x63, 0x72, 0x79, 0x70, 0x74, 0x48, 0x00, 0x52,
	0x06, 0x62, 0x63, 0x72, 0x79, 0x70, 0x74, 0x12, 0x52, 0x0a, 0x06, 0x73, 0x63, 0x72, 0x79, 0x70,
	0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x38, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6c, 0x74, 0x6f, 0x6e, 0x70, 0x72, 0x6f, 0x76, 0x69,
	0x61, 0x73, 0x2e, 0x67, 0x6f, 0x70, 0x61, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2e, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x53, 0x63, 0x72, 0x79, 0x70,
	0x74, 0x48, 0x00, 0x52, 0x06, 0x73, 0x63, 0x72, 0x79, 0x70, 0x74, 0x12, 0x52, 0x0a, 0x06, 0x70,
	0x62, 0x6b, 0x64, 0x66, 0x32, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x38, 0x2e, 0x63, 0x6f,
	0x6d, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6c, 0x74, 0x6f, 0x6e, 0x70,
	0x72, 0x6f, 0x76, 0x69, 0x61, 0x73, 0x2e, 0x67, 0x6f, 0x70, 0x61, 0x73, 0x73, 0x6c, 0x69, 0x62,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x50,
	0x42, 0x4b, 0x44, 0x46, 0x32, 0x48, 0x00, 0x52, 0x06, 0x70, 0x62, 0x6b, 0x64, 0x66, 0x32, 0x42,
	0x11, 0x0a, 0x0f, 0x68, 0x61, 0x73, 0x68, 0x65, 0x64, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f,
	0x72, 0x64, 0x42, 0x2a, 0x5a, 0x28, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x43, 0x6f, 0x6c, 0x74, 0x6f, 0x6e, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x61, 0x73, 0x2f, 0x67,
	0x6f, 0x70, 0x61, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_gopasslib_proto_rawDescOnce sync.Once
	file_proto_gopasslib_proto_rawDescData = file_proto_gopasslib_proto_rawDesc
)

func file_proto_gopasslib_proto_rawDescGZIP() []byte {
	file_proto_gopasslib_proto_rawDescOnce.Do(func() {
		file_proto_gopasslib_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_gopasslib_proto_rawDescData)
	})
	return file_proto_gopasslib_proto_rawDescData
}

var file_proto_gopasslib_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_proto_gopasslib_proto_goTypes = []interface{}{
	(*PasswordArgon2)(nil),    // 0: com.github.coltonprovias.gopasslib.proto.PasswordArgon2
	(*PasswordBcrypt)(nil),    // 1: com.github.coltonprovias.gopasslib.proto.PasswordBcrypt
	(*PasswordScrypt)(nil),    // 2: com.github.coltonprovias.gopasslib.proto.PasswordScrypt
	(*PasswordPBKDF2)(nil),    // 3: com.github.coltonprovias.gopasslib.proto.PasswordPBKDF2
	(*PasswordContainer)(nil), // 4: com.github.coltonprovias.gopasslib.proto.PasswordContainer
}
var file_proto_gopasslib_proto_depIdxs = []int32{
	0, // 0: com.github.coltonprovias.gopasslib.proto.PasswordContainer.argon2:type_name -> com.github.coltonprovias.gopasslib.proto.PasswordArgon2
	1, // 1: com.github.coltonprovias.gopasslib.proto.PasswordContainer.bcrypt:type_name -> com.github.coltonprovias.gopasslib.proto.PasswordBcrypt
	2, // 2: com.github.coltonprovias.gopasslib.proto.PasswordContainer.scrypt:type_name -> com.github.coltonprovias.gopasslib.proto.PasswordScrypt
	3, // 3: com.github.coltonprovias.gopasslib.proto.PasswordContainer.pbkdf2:type_name -> com.github.coltonprovias.gopasslib.proto.PasswordPBKDF2
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_proto_gopasslib_proto_init() }
func file_proto_gopasslib_proto_init() {
	if File_proto_gopasslib_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_gopasslib_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PasswordArgon2); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_gopasslib_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PasswordBcrypt); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_gopasslib_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PasswordScrypt); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_gopasslib_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PasswordPBKDF2); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_gopasslib_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PasswordContainer); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_proto_gopasslib_proto_msgTypes[4].OneofWrappers = []interface{}{
		(*PasswordContainer_Argon2)(nil),
		(*PasswordContainer_Bcrypt)(nil),
		(*PasswordContainer_Scrypt)(nil),
		(*PasswordContainer_Pbkdf2)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_gopasslib_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proto_gopasslib_proto_goTypes,
		DependencyIndexes: file_proto_gopasslib_proto_depIdxs,
		MessageInfos:      file_proto_gopasslib_proto_msgTypes,
	}.Build()
	File_proto_gopasslib_proto = out.File
	file_proto_gopasslib_proto_rawDesc = nil
	file_proto_gopasslib_proto_goTypes = nil
	file_proto_gopasslib_proto_depIdxs = nil
}