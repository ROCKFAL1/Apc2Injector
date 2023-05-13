#include <iostream>
#include <vector>
#include <deque>
#include <string>
#include <type_traits>

#include <wil/resource.h>
#include <xbyak/xbyak.h>

#include <tlhelp32.h>
#include <windows.h>

[[noreturn]] void throw_last_error(DWORD err = GetLastError()) {
	throw std::system_error{static_cast<int>(err), std::system_category()};
}

namespace details {

template <class Fn>
struct tl_enum_entry;

template <class EntryType>
struct tl_enum_entry<BOOL(*)(HANDLE, EntryType)> {
	using type = std::remove_pointer_t<EntryType>;
};

template <class Fn>
using tl_enum_entry_t = typename tl_enum_entry<Fn>::type;

template <auto FnFirst, auto FnNext, class Condition>
auto tl_enum_helper(Condition&& cond, HANDLE snapshot) {
	using entry_t = tl_enum_entry_t<decltype(FnFirst)>;
	entry_t entry{sizeof(entry_t)};

	if (!FnFirst(snapshot, std::addressof(entry))) {
		throw_last_error();
	}

	std::deque<entry_t> result;
	do {
		if (cond(entry)) result.push_back(entry);	
	} while (FnNext(snapshot, std::addressof(entry)));

	return result;
}

void* make_remote_helper(HANDLE process, const void* buffer, 
		size_t sz, DWORD protect) {
	void* allocation{VirtualAllocEx(process, nullptr, sz,
			MEM_COMMIT, protect)};
	if (!allocation) {
		throw_last_error();
	}

	if (!WriteProcessMemory(process, allocation,
				buffer, sz, nullptr)) {
		throw_last_error();
	};

	return allocation;
}

} // namespace details

std::vector<std::wstring> get_cli_args() {
	int argc;
	const auto* argv{CommandLineToArgvW(GetCommandLineW(), &argc)};

	std::vector<std::wstring> result;
	result.reserve(argc);
	for (auto start{argv}, end{start + argc};
				argv < end; ++argv) {
		result.emplace_back(*argv);
	}

	return result;
}

template <class Condition>
auto process_enum_helper(Condition&& cond, HANDLE snapshot) {
	return details::tl_enum_helper<&Process32FirstW, &Process32NextW>(
			std::forward<Condition>(cond), snapshot);
}

template <class Condition>
auto thread_enum_helper(Condition&& cond, HANDLE snapshot) {
	return details::tl_enum_helper<&Thread32First, &Thread32Next>(
			std::forward<Condition>(cond), snapshot);
}


std::wstring get_file_full_path(const std::wstring& file_path) {
	auto required_sz{GetFullPathNameW(file_path.data(), 0, nullptr, nullptr)};
	if (!required_sz) {
		throw_last_error();
	}

	std::wstring result;
	result.resize(required_sz - 1); 

	if (auto sz{GetFullPathNameW(file_path.data(), required_sz, result.data(), nullptr)};
				sz != required_sz - 1 || sz == 0) {
		throw_last_error();
	}

	return result;
}

struct load_library_as_apc : Xbyak::CodeGenerator {
	load_library_as_apc() {
		const auto kernel32{GetModuleHandleW(L"kernel32")};
		const auto load_library{GetProcAddress(kernel32, "LoadLibraryW")};

		push(rax);
		sub(rsp, 0x20);
		mov(rax, reinterpret_cast<std::uintptr_t>(load_library));
		call(rax);
		add(rsp, 0x20);
		pop(rax);
		ret();
	}
};


std::uintptr_t make_remote_string(HANDLE process, const std::wstring& str) {
	auto buffer_size{(str.size() + 1) * sizeof(wchar_t)};
	return reinterpret_cast<std::uintptr_t>(details::make_remote_helper(
			process, str.data(), buffer_size, PAGE_READWRITE));
}

PAPCFUNC make_remote_apc(HANDLE process, const Xbyak::CodeGenerator& gen) {
	return static_cast<PAPCFUNC>(details::make_remote_helper(
			process, gen.getCode(), gen.getSize(), PAGE_EXECUTE_READWRITE));
}

DWORD get_process_main_thread(HANDLE process, HANDLE snapshot) {
	auto pid{GetProcessId(process)};
	auto threads{thread_enum_helper([pid] (THREADENTRY32& entry) { 
		return entry.th32OwnerProcessID == pid;
	}, snapshot)};

	auto creation_time{[](const THREADENTRY32& entry) -> size_t {
		wil::unique_handle h{OpenThread(THREAD_QUERY_INFORMATION, false, entry.th32ThreadID)};
		FILETIME creation;
		FILETIME dummy_exit, dummy_kernel, dummy_user;
		if (!GetThreadTimes(h.get(), &creation, &dummy_exit, &dummy_kernel, &dummy_user)) {
			return std::numeric_limits<size_t>::max();
		}
		size_t result{creation.dwHighDateTime};
		result <<= sizeof(creation.dwHighDateTime) * CHAR_BIT;
		return result | creation.dwLowDateTime;
	}};

	auto it{std::min_element(threads.begin(), threads.end(),
			[&](const THREADENTRY32& lhs, const THREADENTRY32& rhs) {
		return creation_time(lhs) < creation_time(rhs);
	})};
	
	return it->th32ThreadID;
}

DWORD get_pid_by_exe(const std::wstring& exe_name, HANDLE snapshot) {
	return process_enum_helper(
		[&](PROCESSENTRY32W& entry) {
			return entry.szExeFile == exe_name;
		}, snapshot).at(0).th32ProcessID;
}

int main() try {
	auto args{get_cli_args()};
	auto dll_path{get_file_full_path(args.at(1))};
	auto& target_exe{args.at(2)};

	wil::unique_handle snapshot{CreateToolhelp32Snapshot(
			TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0)};
	
	wil::unique_handle target_process{OpenProcess(
			PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, 
			get_pid_by_exe(target_exe, snapshot.get()))};

	auto remote_apc{make_remote_apc(
			target_process.get(), load_library_as_apc{})};

	auto remote_dll_path{make_remote_string(
			target_process.get(), dll_path)};

	auto main_tid{get_process_main_thread(
			target_process.get(), snapshot.get())};

	wil::unique_handle main_thread{OpenThread(
			THREAD_SET_CONTEXT, false, main_tid)};

	if (!QueueUserAPC2(remote_apc, main_thread.get(), 
				remote_dll_path, QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC)) {
		throw_last_error();
	}
	
	return 0;
}	catch (const std::system_error& e) {
	auto ec{e.code().value()};
	std::cout << ec << " " << e.what() << std::endl;
	return ec;
} catch (const std::exception& e) {
	std::cout << e.what() << std::endl;
	return -1;
}
