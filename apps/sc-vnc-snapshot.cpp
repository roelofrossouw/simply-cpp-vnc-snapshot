// sc-vnc-snapshot, the program: one screenshot of a VNC server (an iDRAC console, say) as a PNG
// file. The password comes from a file or the environment, never the command line.
#include <sc/vnc-snapshot/vnc.h>

#include <sc/core/params.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>

namespace {
    constexpr int usage_error = 2, auth_failed = 3, connection_failed = 4;
    constexpr const char *password_variable = "SC_VNC_PASSWORD";

    struct usage : std::invalid_argument {
        using std::invalid_argument::invalid_argument;
    };

    // HOST:PORT, [IPv6]:PORT, or HOST alone for 5900. A port below 100 is a display number, as
    // VNC viewers take it (:1 is 5901).
    std::pair<std::string, std::uint16_t> server_of(const std::string &text) {
        std::string host = text, port;
        if (text.starts_with('[')) {
            const auto end = text.find(']');
            if (end == std::string::npos) throw usage("no ] in " + text);
            host = text.substr(1, end - 1);
            if (end + 1 < text.size()) {
                if (text[end + 1] != ':') throw usage("expected :PORT after ] in " + text);
                port = text.substr(end + 2);
            }
        } else if (const auto colon = text.rfind(':'); colon != std::string::npos) {
            host = text.substr(0, colon);
            port = text.substr(colon + 1);
        }
        if (host.empty()) throw usage("no host in " + text);
        if (port.empty()) return {host, 5900};
        if (!std::ranges::all_of(port, [](const unsigned char c) { return std::isdigit(c); }) || port.size() > 5)
            throw usage("invalid port in " + text);
        const auto number = std::stoi(port);
        if (number < 1 || number > 65535) throw usage("invalid port in " + text);
        return {host, static_cast<std::uint16_t>(number < 100 ? 5900 + number : number)};
    }

    std::optional<std::string> password_from(const sc::params &args) {
        if (const auto *file = args.lookup("password-file")) {
            const auto path = file->get<std::string>();
            std::ifstream in{path};
            if (!in) throw usage("can't read the password file " + path);
            std::string line;
            std::getline(in, line);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            return line;
        }
        if (const char *value = std::getenv(password_variable)) return std::string{value};
        return std::nullopt;
    }
} // namespace

int main(int argc, char **argv) {
    const sc::params args{argc, argv, {
        {"name", "sc-vnc-snapshot"},
        {"description", "Takes one screenshot of a VNC server, such as an iDRAC console, and writes it as a PNG."},
        {"version", SC_VNC_SNAPSHOT_VERSION},
        {"epilog", "It connects as a shared viewer (other viewers stay connected), signs in with no security or with VNC "
                   "authentication, asks once for the whole screen in the Raw encoding, writes OUTPUT when every pixel has "
                   "arrived, and disconnects. The password is read from --password-file (its first line) or else from the "
                   "SC_VNC_PASSWORD environment variable; it is never taken from the command line or printed."},
        {"options", {
            {"password-file", {{"short", "p"}, {"value", "FILE"}, {"help", "read the VNC password from the first line of FILE"}}},
            {"timeout", {{"short", "t"}, {"type", "integer"}, {"value", "SECONDS"}, {"default", 60},
                         {"help", "the longest to wait for the server to say something (connecting: at most 15 s)"}}},
            {"quiet", {{"short", "q"}, {"type", "boolean"}, {"help", "print nothing when it worked"}}}}},
        {"positional", {
            {"server", {{"help", "HOST:PORT (or [IPv6]:PORT; HOST alone is port 5900, and :N below 100 is display N, port 5900+N)"}}},
            {"output", {{"help", "the PNG file to write"}}}}}}};
    try {
        const auto [host, port] = server_of(args.as<std::string>("server"));
        const auto output = args.as<std::string>("output");
        auto extension = std::filesystem::path{output}.extension().string();
        std::ranges::transform(extension, extension.begin(), [](const unsigned char c) { return std::tolower(c); });
        if (extension != ".png") throw usage("OUTPUT must be a .png file: " + output);
        const auto seconds = args.as<int>("timeout");
        if (seconds < 1) throw usage("--timeout must be at least 1");

        sc::vnc::options options{.password = password_from(args), .read_timeout = std::chrono::seconds{seconds}};
        options.connect_timeout = std::min<std::chrono::milliseconds>(options.connect_timeout, options.read_timeout);
        sc::vnc::client vnc{host, port, std::move(options)};
        const auto screen = vnc.snapshot();
        vnc.close();
        screen.save_png(output);
        if (!args.as<bool>("quiet"))
            std::cout << output << ": " << screen.size().width() << "x" << screen.size().height() << " from \"" << vnc.desktop_name() << "\"\n";
        return 0;
    } catch (const usage &problem) {
        std::cerr << "sc-vnc-snapshot: " << problem.what() << '\n';
        return usage_error;
    } catch (const sc::vnc::auth_error &problem) {
        std::cerr << "sc-vnc-snapshot: " << problem.what() << '\n';
        return auth_failed;
    } catch (const std::exception &problem) {
        std::cerr << "sc-vnc-snapshot: " << problem.what() << '\n';
        return connection_failed;
    }
}
