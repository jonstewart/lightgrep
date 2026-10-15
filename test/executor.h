/*
 * Copyright 2025 LevelBlue
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#pragma once

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <thread>
#include <vector>

#include "boost_asio.h"

class Executor {
public:
  Executor(size_t n = std::thread::hardware_concurrency()):
    service_(n), work_(boost::asio::make_work_guard(service_))
  {
    for (size_t i = 0; i < n; ++i) {
      pool_.emplace_back([this](){ service_.run(); });
    }
  }

  ~Executor() {
    work_.reset();
    for (std::thread& t : pool_) { t.join(); }
  }

  template <typename F>
  void submit(F task) {
    boost::asio::post(service_, task);
  }

protected:
  std::vector<std::thread> pool_;
  boost::asio::io_context service_;
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_;
};
