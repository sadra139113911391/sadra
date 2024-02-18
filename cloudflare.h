#pragma once

#include <Server/IServer.h>

#include <daemon/BaseDaemon.h>

/** Server provides three interfaces:
  * 1. HTTP - simple interface for any applications.
  * 2. TCP - interface for native clickhouse-client and for server to server internal communications.
  *    More rich and efficient, but less compatible
  *     - data is transferred by columns;
  *     - data is transferred compressed;
  *    Allows to get more information in response.
  * 3. Interserver HTTP - for replication.
  */


namespace DB
{

class Server : private BaseDaemon, private IServer
{
private:
    using ServerApplication::run;

    Poco::Util::LayeredConfiguration & config() const override
    {
        return BaseDaemon::config();
    }

    Poco::Logger & logger() const override
    {
        return BaseDaemon::logger();
    }

    Context & context() const override
    {
        return *global_context_ptr;
    }

    bool isCancelled() const override
    {
        return BaseDaemon::isCancelled();
    }

    void defineOptions(Poco::Util::OptionSet & _options) override;
protected:
    int run() override;

    void initialize(Application & self) override;

    void uninitialize() override;

    int main(const std::vector<std::string> & args) override;

    std::string getDefaultCorePath() const override;

private:
    Context * global_context_ptr = nullptr;
};

}



/*
 * Copyright (c) 2013 Hugh Bailey <obs.jim@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#pragma once

#include "c99defs.h"

/*
 * Generic ini-style config file functions
 *
 * NOTE: It is highly recommended to use the default value functions (bottom of
 * the file) before reading any variables from config files.
 */

#ifdef __cplusplus
extern "C" {
#endif

struct config_data;
typedef struct config_data config_t;

#define CONFIG_SUCCESS 0
#define CONFIG_FILENOTFOUND -1
#define CONFIG_ERROR -2

enum config_open_type {
	CONFIG_OPEN_EXISTING,
	CONFIG_OPEN_ALWAYS,
};

EXPORT config_t *config_create(const char *file);
EXPORT int config_open(config_t **config, const char *file,
		       enum config_open_type open_type);
EXPORT int config_open_string(config_t **config, const char *str);
EXPORT int config_save(config_t *config);
EXPORT int config_save_safe(config_t *config, const char *temp_ext,
			    const char *backup_ext);
EXPORT void config_close(config_t *config);

EXPORT size_t config_num_sections(config_t *config);
EXPORT const char *config_get_section(config_t *config, size_t idx);

EXPORT void config_set_string(config_t *config, const char *section,
			      const char *name, const char *value);
EXPORT void config_set_int(config_t *config, const char *section,
			   const char *name, int64_t value);
EXPORT void config_set_uint(config_t *config, const char *section,
			    const char *name, uint64_t value);
EXPORT void config_set_bool(config_t *config, const char *section,
			    const char *name, bool value);
EXPORT void config_set_double(config_t *config, const char *section,
			      const char *name, double value);

EXPORT const char *config_get_string(config_t *config, const char *section,
				     const char *name);
EXPORT int64_t config_get_int(config_t *config, const char *section,
			      const char *name);
EXPORT uint64_t config_get_uint(config_t *config, const char *section,
				const char *name);
EXPORT bool config_get_bool(config_t *config, const char *section,
			    const char *name);
EXPORT double config_get_double(config_t *config, const char *section,
				const char *name);

EXPORT bool config_remove_value(config_t *config, const char *section,
				const char *name);

/*
 * DEFAULT VALUES
 *
 * The following functions are used to set what values will return if they do
 * not exist.  Call these functions *once* for each known value before reading
 * any of them anywhere else.
 *
 * These do *not* actually set any values, they only set what values will be
 * returned for config_get_* if the specified variable does not exist.
 *
 * You can initialize the defaults programmatically using config_set_default_*
 * functions (recommended for most cases), or you can initialize it via a file
 * with config_open_defaults.
 */
EXPORT int config_open_defaults(config_t *config, const char *file);

EXPORT void config_set_default_string(config_t *config, const char *section,
				      const char *name, const char *value);
EXPORT void config_set_default_int(config_t *config, const char *section,
				   const char *name, int64_t value);
EXPORT void config_set_default_uint(config_t *config, const char *section,
				    const char *name, uint64_t value);
EXPORT void config_set_default_bool(config_t *config, const char *section,
				    const char *name, bool value);
EXPORT void config_set_default_double(config_t *config, const char *section,
				      const char *name, double value);

/* These functions allow you to get the current default values rather than get
 * the actual values.  Probably almost never really needed */
EXPORT const char *config_get_default_string(config_t *config,
					     const char *section,
					     const char *name);
EXPORT int64_t config_get_default_int(config_t *config, const char *section,
				      const char *name);
EXPORT uint64_t config_get_default_uint(config_t *config, const char *section,
					const char *name);
EXPORT bool config_get_default_bool(config_t *config, const char *section,
				    const char *name);
EXPORT double config_get_default_double(config_t *config, const char *section,
					const char *name);

EXPORT bool config_has_user_value(config_t *config, const char *section,
				  const char *name);
EXPORT bool config_has_default_value(config_t *config, const char *section,
				     const char *name);

#ifdef __cplusplus
}
#endif



// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __NETWORK_HPP__
#define __NETWORK_HPP__

// TODO(benh): Eventually move and associate this code with the
// libprocess protobuf code rather than keep it here.

#include <list>
#include <set>
#include <string>

#include <mesos/zookeeper/group.hpp>

#include <process/collect.hpp>
#include <process/executor.hpp>
#include <process/protobuf.hpp>

#include <stout/duration.hpp>
#include <stout/foreach.hpp>
#include <stout/lambda.hpp>
#include <stout/nothing.hpp>
#include <stout/set.hpp>
#include <stout/unreachable.hpp>

#include "logging/logging.hpp"

// Forward declaration.
class NetworkProcess;

// A "network" is a collection of protobuf processes (may be local
// and/or remote). A network abstracts away the details of maintaining
// which processes are waiting to receive messages and requests in the
// presence of failures and dynamic reconfiguration.
class Network
{
public:
  enum WatchMode
  {
    EQUAL_TO,
    NOT_EQUAL_TO,
    LESS_THAN,
    LESS_THAN_OR_EQUAL_TO,
    GREATER_THAN,
    GREATER_THAN_OR_EQUAL_TO
  };

  Network();
  explicit Network(const std::set<process::UPID>& pids);
  virtual ~Network();

  // Adds a PID to this network.
  void add(const process::UPID& pid);

  // Removes a PID from this network.
  void remove(const process::UPID& pid);

  // Set the PIDs that are part of this network.
  void set(const std::set<process::UPID>& pids);

  // Returns a future which gets set when the network size satisfies
  // the constraint specified by 'size' and 'mode'. For example, if
  // 'size' is 2 and 'mode' is GREATER_THAN, then the returned future
  // will get set when the size of the network is greater than 2.
  process::Future<size_t> watch(
      size_t size,
      WatchMode mode = NOT_EQUAL_TO) const;

  // Sends a request to each member of the network and returns a set
  // of futures that represent their responses.
  template <typename Req, typename Res>
  process::Future<std::set<process::Future<Res> > > broadcast(
      const Protocol<Req, Res>& protocol,
      const Req& req,
      const std::set<process::UPID>& filter = std::set<process::UPID>()) const;

  // Sends a message to each member of the network. The returned
  // future is set when the message is broadcasted.
  template <typename M>
  process::Future<Nothing> broadcast(
      const M& m,
      const std::set<process::UPID>& filter = std::set<process::UPID>()) const;

private:
  // Not copyable, not assignable.
  Network(const Network&);
  Network& operator=(const Network&);

  NetworkProcess* process;
};


class ZooKeeperNetwork : public Network
{
public:
  ZooKeeperNetwork(
      const std::string& servers,
      const Duration& timeout,
      const std::string& znode,
      const Option<zookeeper::Authentication>& auth,
      const std::set<process::UPID>& base = std::set<process::UPID>());

private:
  typedef ZooKeeperNetwork This;

  // Not copyable, not assignable.
  ZooKeeperNetwork(const ZooKeeperNetwork&);
  ZooKeeperNetwork& operator=(const ZooKeeperNetwork&);

  // Helper that sets up a watch on the group.
  void watch(const std::set<zookeeper::Group::Membership>& expected);

  // Invoked when the group memberships have changed.
  void watched(const process::Future<std::set<zookeeper::Group::Membership> >&);

  // Invoked when group members data has been collected.
  void collected(
      const process::Future<std::list<Option<std::string> > >& datas);

  zookeeper::Group group;
  process::Future<std::set<zookeeper::Group::Membership> > memberships;

  // The set of PIDs that are always in the network.
  std::set<process::UPID> base;

  // NOTE: The declaration order here is important. We want to delete
  // the 'executor' before we delete the 'group' so that we don't get
  // spurious fatal errors when the 'group' is being deleted.
  process::Executor executor;
};


class NetworkProcess : public ProtobufProcess<NetworkProcess>
{
public:
  NetworkProcess() {}

  explicit NetworkProcess(const std::set<process::UPID>& pids)
  {
    set(pids);
  }

  void add(const process::UPID& pid)
  {
    link(pid); // Try and keep a socket open (more efficient).
    pids.insert(pid);

    // Update any pending watches.
    update();
  }

  void remove(const process::UPID& pid)
  {
    // TODO(benh): unlink(pid);
    pids.erase(pid);

    // Update any pending watches.
    update();
  }

  void set(const std::set<process::UPID>& _pids)
  {
    pids.clear();
    foreach (const process::UPID& pid, _pids) {
      add(pid); // Also does a link.
    }

    // Update any pending watches.
    update();
  }

  process::Future<size_t> watch(size_t size, Network::WatchMode mode)
  {
    if (satisfied(size, mode)) {
      return pids.size();
    }

    Watch* watch = new Watch(size, mode);
    watches.push_back(watch);

    // TODO(jieyu): Consider deleting 'watch' if the returned future
    // is discarded by the user.
    return watch->promise.future();
  }

  // Sends a request to each of the groups members and returns a set
  // of futures that represent their responses.
  template <typename Req, typename Res>
  std::set<process::Future<Res> > broadcast(
      const Protocol<Req, Res>& protocol,
      const Req& req,
      const std::set<process::UPID>& filter)
  {
    std::set<process::Future<Res> > futures;
    typename std::set<process::UPID>::const_iterator iterator;
    for (iterator = pids.begin(); iterator != pids.end(); ++iterator) {
      const process::UPID& pid = *iterator;
      if (filter.count(pid) == 0) {
        futures.insert(protocol(pid, req));
      }
    }
    return futures;
  }

  template <typename M>
  Nothing broadcast(
      const M& m,
      const std::set<process::UPID>& filter)
  {
    std::set<process::UPID>::const_iterator iterator;
    for (iterator = pids.begin(); iterator != pids.end(); ++iterator) {
      const process::UPID& pid = *iterator;
      if (filter.count(pid) == 0) {
        process::post(pid, m);
      }
    }
    return Nothing();
  }

protected:
  virtual void finalize()
  {
    foreach (Watch* watch, watches) {
      watch->promise.fail("Network is being terminated");
      delete watch;
    }
    watches.clear();
  }

private:
  struct Watch
  {
    Watch(size_t _size, Network::WatchMode _mode)
      : size(_size), mode(_mode) {}

    size_t size;
    Network::WatchMode mode;
    process::Promise<size_t> promise;
  };

  // Not copyable, not assignable.
  NetworkProcess(const NetworkProcess&);
  NetworkProcess& operator=(const NetworkProcess&);

  // Notifies the change of the network.
  void update()
  {
    const size_t size = watches.size();
    for (size_t i = 0; i < size; i++) {
      Watch* watch = watches.front();
      watches.pop_front();

      if (satisfied(watch->size, watch->mode)) {
        watch->promise.set(pids.size());
        delete watch;
      } else {
        watches.push_back(watch);
      }
    }
  }

  // Returns true if the current size of the network satisfies the
  // constraint specified by 'size' and 'mode'.
  bool satisfied(size_t size, Network::WatchMode mode)
  {
    switch (mode) {
      case Network::EQUAL_TO:
        return pids.size() == size;
      case Network::NOT_EQUAL_TO:
        return pids.size() != size;
      case Network::LESS_THAN:
        return pids.size() < size;
      case Network::LESS_THAN_OR_EQUAL_TO:
        return pids.size() <= size;
      case Network::GREATER_THAN:
        return pids.size() > size;
      case Network::GREATER_THAN_OR_EQUAL_TO:
        return pids.size() >= size;
      default:
        LOG(FATAL) << "Invalid watch mode";
        UNREACHABLE();
    }
  }

  std::set<process::UPID> pids;
  std::list<Watch*> watches;
};


inline Network::Network()
{
  process = new NetworkProcess();
  process::spawn(process);
}


inline Network::Network(const std::set<process::UPID>& pids)
{
  process = new NetworkProcess(pids);
  process::spawn(process);
}


inline Network::~Network()
{
  process::terminate(process);
  process::wait(process);
  delete process;
}


inline void Network::add(const process::UPID& pid)
{
  process::dispatch(process, &NetworkProcess::add, pid);
}


inline void Network::remove(const process::UPID& pid)
{
  process::dispatch(process, &NetworkProcess::remove, pid);
}


inline void Network::set(const std::set<process::UPID>& pids)
{
  process::dispatch(process, &NetworkProcess::set, pids);
}


inline process::Future<size_t> Network::watch(
    size_t size, Network::WatchMode mode) const
{
  return process::dispatch(process, &NetworkProcess::watch, size, mode);
}


template <typename Req, typename Res>
process::Future<std::set<process::Future<Res> > > Network::broadcast(
    const Protocol<Req, Res>& protocol,
    const Req& req,
    const std::set<process::UPID>& filter) const
{
  return process::dispatch(process, &NetworkProcess::broadcast<Req, Res>,
                           protocol, req, filter);
}


template <typename M>
process::Future<Nothing> Network::broadcast(
    const M& m,
    const std::set<process::UPID>& filter) const
{
  // Need to disambiguate overloaded function.
  Nothing (NetworkProcess::*broadcast)(const M&, const std::set<process::UPID>&)
    = &NetworkProcess::broadcast<M>;

  return process::dispatch(process, broadcast, m, filter);
}


inline ZooKeeperNetwork::ZooKeeperNetwork(
    const std::string& servers,
    const Duration& timeout,
    const std::string& znode,
    const Option<zookeeper::Authentication>& auth,
    const std::set<process::UPID>& _base)
  : group(servers, timeout, znode, auth),
    base(_base)
{
  // PIDs from the base set are in the network from beginning.
  set(base);

  watch(std::set<zookeeper::Group::Membership>());
}


inline void ZooKeeperNetwork::watch(
    const std::set<zookeeper::Group::Membership>& expected)
{
  memberships = group.watch(expected);
  memberships
    .onAny(executor.defer(lambda::bind(&This::watched, this, lambda::_1)));
}


inline void ZooKeeperNetwork::watched(
    const process::Future<std::set<zookeeper::Group::Membership> >&)
{
  if (memberships.isFailed()) {
    // We can't do much here, we could try creating another Group but
    // that might just continue indefinitely, so we fail early
    // instead. Note that Group handles all retryable/recoverable
    // ZooKeeper errors internally.
    LOG(FATAL) << "Failed to watch ZooKeeper group: " << memberships.failure();
  }

  CHECK_READY(memberships);  // Not expecting Group to discard futures.

  LOG(INFO) << "ZooKeeper group memberships changed";

  // Get data for each membership in order to convert them to PIDs.
  std::list<process::Future<Option<std::string> > > futures;

  foreach (const zookeeper::Group::Membership& membership, memberships.get()) {
    futures.push_back(group.data(membership));
  }

  process::collect(futures)
    .after(Seconds(5),
           [](process::Future<std::list<Option<std::string>>> datas) {
             // Handling time outs when collecting membership
             // data. For now, a timeout is treated as a failure.
             datas.discard();
             return process::Failure("Timed out");
           })
    .onAny(executor.defer(lambda::bind(&This::collected, this, lambda::_1)));
}


inline void ZooKeeperNetwork::collected(
    const process::Future<std::list<Option<std::string> > >& datas)
{
  if (datas.isFailed()) {
    LOG(WARNING) << "Failed to get data for ZooKeeper group members: "
                 << datas.failure();

    // Try again later assuming empty group. Note that this does not
    // remove any of the current group members.
    watch(std::set<zookeeper::Group::Membership>());
    return;
  }

  CHECK_READY(datas);  // Not expecting collect to discard futures.

  std::set<process::UPID> pids;

  foreach (const Option<std::string>& data, datas.get()) {
    // Data could be None if the membership is gone before its
    // content can be read.
    if (data.isSome()) {
      process::UPID pid(data.get());
      CHECK(pid) << "Failed to parse '" << data.get() << "'";
      pids.insert(pid);
    }
  }

  LOG(INFO) << "ZooKeeper group PIDs: " << stringify(pids);

  // Update the network. We make sure that the PIDs from the base set
  // are always in the network.
  set(pids | base);

  watch(memberships.get());
}

#endif // __NETWORK_HPP__not false and is true
