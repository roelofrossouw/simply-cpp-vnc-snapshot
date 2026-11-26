#pragma once

#include <sc/geometry/point.h>
#include <sc/geometry/rect.h>
#include <sc/geometry/size.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// A VNC (RFB 3.3, 3.7 and 3.8) client for one screenshot: it connects, signs in (no security, or
// VNC authentication), asks for the whole screen once, and gives it back as a picture, to save as
// a PNG. It joins as a shared viewer, so other viewers stay connected (an iDRAC allows one VNC
// session; a non-shared client would end it).
//
//     sc::vnc::client vnc{"idrac.example.com", 5901, {.password = password}};
//     const auto screen = vnc.snapshot(); // screen.size() is [1024,768]
//     screen.save_png("console.png");
//
// or, in one call, sc::vnc::snapshot("idrac.example.com", 5901, {.password = password}).
//
// Only the Raw encoding is asked for, which every server has to support. Errors are exceptions:
// sc::vnc::connect_error (no connection: refused, unreachable, timed out), sc::vnc::auth_error
// (a wrong or missing password, or the server refused the session) and sc::vnc::protocol_error
// (anything else the server says that this client can't follow, such as an encoding it didn't
// ask for).
namespace sc::vnc {
    struct error : std::runtime_error {
        using std::runtime_error::runtime_error;
    };
    struct connect_error : error {
        using error::error;
    };
    struct auth_error : error {
        using error::error;
    };
    struct protocol_error : error {
        using error::error;
    };

    struct options {
        // For VNC authentication (security type 2); only its first 8 bytes count. Kept in memory
        // only as long as the client is signing in, and never put in an error message.
        std::optional<std::string> password{};
        std::chrono::milliseconds connect_timeout{std::chrono::seconds{15}};
        // The longest the server may stay silent while the client waits for something.
        std::chrono::milliseconds read_timeout{std::chrono::seconds{60}};
        // Share the desktop with other viewers (ClientInit's shared flag). false asks the server
        // to disconnect them.
        bool shared = true;
    };

    // A screenshot: 8-bit RGB, rows from the top.
    class picture {
    public:
        picture() = default;
        explicit picture(sc::size_i size);

        [[nodiscard]] sc::size_i size() const { return size_; }
        [[nodiscard]] const std::vector<std::uint8_t> &rgb() const { return rgb_; }
        [[nodiscard]] std::vector<std::uint8_t> &rgb() { return rgb_; }
        // The colour at a point, as {red, green, blue}; std::out_of_range off the picture.
        [[nodiscard]] std::array<std::uint8_t, 3> pixel(sc::point_i at) const;

        // The picture as a PNG file's bytes (8-bit RGB, zlib level 6).
        [[nodiscard]] std::string png() const;
        void save_png(const std::filesystem::path &file) const;

    private:
        sc::size_i size_{};
        std::vector<std::uint8_t> rgb_;
    };

    // The RFB security types this client knows.
    enum class security : std::uint8_t { none = 1, vnc_authentication = 2 };

    class client {
    public:
        // Connects, agrees on a protocol version, signs in and reads the server's screen size and
        // name.
        client(const std::string &host, std::uint16_t port, vnc::options options = {});
        ~client();

        client(const client &) = delete;
        client &operator=(const client &) = delete;
        client(client &&) noexcept;
        client &operator=(client &&) noexcept;

        // The protocol version agreed: 3, 7 or 8 (RFB 3.x).
        [[nodiscard]] int protocol_minor() const;
        [[nodiscard]] vnc::security security() const;
        [[nodiscard]] sc::size_i screen_size() const;
        [[nodiscard]] const std::string &desktop_name() const;

        // Asks for the whole screen (one non-incremental update request) and waits until the
        // server has sent every pixel of it.
        [[nodiscard]] picture snapshot();

        // Closes the connection; the destructor does too.
        void close();

    private:
        struct state;
        std::unique_ptr<state> state_;
    };

    // Connects, takes one screenshot and disconnects.
    picture snapshot(const std::string &host, std::uint16_t port, const vnc::options &options = {});

    // VNC authentication's answer to the server's 16-byte challenge: the challenge DES-encrypted
    // (ECB) with the password as the key, cut or zero-padded to 8 bytes, each byte's bits reversed.
    std::array<std::uint8_t, 16> auth_response(std::string_view password, const std::array<std::uint8_t, 16> &challenge);

    // DES (encryption only, one 8-byte block), for auth_response; key and block big-endian.
    std::uint64_t des_encrypt(std::uint64_t key, std::uint64_t block);
} // namespace sc::vnc
