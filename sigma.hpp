#pragma once

#include <algorithm>
#include <format>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#define SIGMA_WIN32
#ifdef SIGMA_WIN32
#include <windows.h>
// ---
#include <psapi.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
#endif

namespace sigma {

namespace impl {

class image_base {
 public:
  virtual ~image_base() {}
  virtual size_t size() const = 0;
  virtual uint8_t* start() const = 0;
};

}  // namespace impl

std::vector<uint8_t> hex2bin(const char* str,
                             std::vector<uint8_t>* wildcard = nullptr) {
  size_t len = strlen(str);
  assert(len % 2 == 0);
  std::vector<uint8_t> ret(len / 2, 0);
  constexpr auto hextob = [](char ch) {
    if (ch >= '0' && ch <= '9')
      return ch - '0';
    if (ch >= 'A' && ch <= 'F')
      return ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f')
      return ch - 'a' + 10;
    assert(false && "unexpected char.");
    return 0;
  };
  if (wildcard) {
    wildcard->clear();
    wildcard->resize(len);
  }
  for (size_t i = 0; i < len / 2; ++i) {
    char c0 = str[i * 2];
    char c1 = str[i * 2 + 1];
    if (wildcard) {
      if (c0 == '?' && c1 == '?') {
        (*wildcard)[i] = 1;
        ret[i] = 0x00;
        continue;
      }
    }
    uint8_t v = 0;
    v |= hextob(c0) << 4;
    v |= hextob(c1);
    ret[i] = v;
  }
  return ret;
}

std::string bin2hex(const void* buf, size_t len) {
  std::stringstream ss;
  for (size_t i = 0; i < len; ++i) {
    const char byte = ((const char*)buf)[i];
    constexpr const char* hex = "0123456789abcdef";
    ss << hex[(byte & 0xF0) >> 4];
    ss << hex[(byte & 0x0F) >> 0];
  }
  std::string str = ss.str();
  return str;
}

struct segment {
  uint8_t* start;
  uint8_t* end;
};

class matcher {
  friend class image;

 public:
  size_t kBaseOffset = 0x400000;

  void reset() { results_ = {image_->start()}; }

  impl::image_base& image() const { return *image_; }
  std::vector<uint8_t*> results() const noexcept { return results_; }
  uint8_t* ptr() const { return results_.front(); }
  size_t offset() const { return ptr() - image_->start() + kBaseOffset; }
  size_t raw_offset() const { return ptr() - image_->start(); }
  template <typename T>
  T read(int offset = 0) const {
    uint8_t* ptr = results_.front() + offset;
    T result = *((T*)ptr);
    return result;
  }

  matcher& search_hex(const std::string_view& str,
                      bool backward = false,
                      size_t limit = 0) {
    std::vector<uint8_t> pattern, wildcard;
    pattern = hex2bin(str.data(), &wildcard);
    segment s{ptr(),
              limit ? (ptr() + limit) : (image_->start() + image_->size())};
    results_ = search(pattern, wildcard, s, backward);
    return *this;
  }

  matcher& search_hex(const char* str,
                      bool backward = false,
                      size_t limit = 0) {
    std::vector<uint8_t> pattern, wildcard;
    pattern = hex2bin(str, &wildcard);
    segment s{ptr(),
              limit ? (ptr() + limit) : (image_->start() + image_->size())};
    results_ = search(pattern, wildcard, s, backward);
    return *this;
  }

  matcher& search_string(const char* str) {
    std::vector<uint8_t> pattern(str, str + strlen(str));
    segment s{ptr(), image_->start() + image_->size()};
    results_ = search(pattern, {}, s);
    return *this;
  }

  matcher& offsetted(size_t offset) {
    for (uint8_t*& ptr : results_) {
      ptr += offset;
    }
    return *this;
  }

  matcher& nth(size_t n) {
    results_ = {results_.at(n)};
    return *this;
  }

  std::vector<uint8_t*> search(const std::vector<uint8_t>& pattern,
                               const std::vector<uint8_t>& wildcard = {},
                               const segment& segment = {},
                               bool backward = false) const {
    if (pattern.empty()) {
      assert(false && "pattern is empty.");
      return {};
    }

    uint8_t* start = segment.start;
    uint8_t* end = segment.end;
    if (start == NULL)
      start = image_->start();
    if (end == NULL)
      end = image_->start() + image_->size() - 1;
    if (start < image_->start()) {
      start = image_->start();
    }
    if (end >= image_->start() + image_->size() - 1) {
      end = image_->start() + image_->size() - 1;
    }
    assert(start >= image_->start());
    assert(end <= image_->start() + image_->size());

    std::vector<uint8_t*> results;
    if (backward) {
      for (uint8_t* data = end; data != start; data--) {
        bool found = true;
        for (size_t i = 0; (i < pattern.size()) && (data + i != start); ++i) {
          if (i < wildcard.size() && wildcard[i] != 0) {
            continue;
          }
          uint8_t val = *(data + i);
          if (val != pattern[i]) {
            found = false;
            break;
          }
        }
        if (found) {
          results.push_back(data);
        }
      }
    } else {
      for (uint8_t* data = start; data != end; data++) {
        bool found = true;
        for (size_t i = 0; (i < pattern.size()) && (data + i != end); ++i) {
          if (i < wildcard.size() && wildcard[i] != 0) {
            continue;
          }
          uint8_t val = *(data + i);
          if (val != pattern[i]) {
            found = false;
            break;
          }
        }
        if (found) {
          results.push_back(data);
        }
      }
    }
    return results;
  }

  matcher& search_procedure_start(size_t limit = 0) {
    segment s{ptr() - (limit ? limit : 10000), ptr()};
    results_.clear();

    std::vector<uint8_t*> temp;
    temp = search({0x55, 0x8b, 0xec}, {}, s, true);  // push ebp, mov ebp, esp
    for (uint8_t* ptr : temp) {
      results_.emplace_back(ptr);
    }

    temp = search({0xcc, 0xcc}, {}, s, true);  // padding
    for (uint8_t* p : temp) {
      while (p != ptr()) {
        if (*p != 0xcc) {
          results_.emplace_back(p);
          break;
        }
        p++;
      }
    }

    std::sort(results_.begin(), results_.end(), std::greater<uint8_t*>());
    auto it = std::unique(results_.begin(), results_.end());
    results_.erase(it, results_.end());

    return *this;
  }

  size_t relative_target() const {
    size_t base = offset();
    uint8_t op0 = *ptr();
    if (op0 == 0xe8 || op0 == 0xe9 || op0 == 0x9a) {
      int32_t rel = *(int32_t*)(ptr() + 1);
      size_t target = base + 5 + rel;
      return target;
    } else {
      assert(false && "unexpected opcode.");
      return 0ull;
    }
  }

 private:
  matcher(impl::image_base* image) : image_(image) {
    results_.push_back(image->start());
  }
  matcher(impl::image_base* image, uint8_t* start) : image_(image) {
    assert(start >= image->start());
    assert(start < image->start() + image->size());
    results_.push_back(start);
  }

  impl::image_base* image_;
  std::vector<uint8_t*> results_;
};

class image : public impl::image_base {
  friend image from_memory(void* ptr, size_t size);
  friend image from_process(void* handle);
  friend image from_current_process();
  friend image from_file(const char* path);

 public:
  uint8_t* start() const override { return start_; }
  size_t size() const override { return size_; }

  matcher matcher() {
    sigma::matcher matcher(this);
    return matcher;
  }

 private:
  image() : start_(), size_() {}

 private:
  std::shared_ptr<void> handle_;
  std::vector<uint8_t> buf_;
  uint8_t* start_;
  size_t size_;

  struct section {};
  std::vector<section> sections_;
};

image from_memory(void* ptr, size_t size) {
  image image;
  image.start_ = (uint8_t*)ptr;
  image.size_ = size;
  return image;
}

// TODO:
image from_process(void* handle);

// TODO:
image from_current_process();

image from_file(const char* path) {
  std::ifstream ifs(path, std::ios::binary);
  auto size = ifs.seekg(0, std::ios::end).tellg();
  std::vector<uint8_t> buffer((size_t)size);
  ifs.seekg(0, std::ios::beg);
  ifs.read((char*)buffer.data(), buffer.size());

  image image;
  image.buf_ = std::move(buffer);
  image.start_ = (uint8_t*)image.buf_.data();
  image.size_ = image.buf_.size();

  return image;
}

void print(const matcher& matcher) {
  std::cout << std::format("matched:{}", matcher.results().size()) << std::endl;
  for (const uint8_t* ptr : matcher.results()) {
    size_t offset = (ptr - matcher.image().start()) + matcher.kBaseOffset;
    std::cout << std::format("- ptr:{} offset:{:x}", (void*)ptr, offset)
              << std::endl;
  }
}

}  // namespace sigma
