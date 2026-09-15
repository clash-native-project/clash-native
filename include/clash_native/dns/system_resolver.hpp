#pragma once

#include <clash_native/core/result.hpp>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <functional>
#include <string>
#include <vector>

namespace clash_native::dns {

class SystemResolver final {
  public:
    using Handler = std::function<void(core::Result<std::vector<boost::asio::ip::address>>)>;

    explicit SystemResolver(boost::asio::io_context &context);

    void resolve(std::string name, Handler handler);
    void cancel() noexcept;

  private:
    boost::asio::ip::tcp::resolver resolver_;
};

} // namespace clash_native::dns
