/*
Copyright (C) 2020 The Falco Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "outputs_file.h"
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>
//#include "banned.h" // This raises a compilation error when certain functions are used
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

std::string falco::outputs::output_file::serialize_message(const message *msg){
	payload["ts"] = msg->ts;
	payload["priority"] = static_cast<int>(msg->priority);
	// payload["msg"] = msg->msg;
	payload["rule"] = msg->rule;
	payload["source"] = msg->source;
	payload["fields"] = msg->fields;
	payload["tags"] = msg->tags;
	return payload.dump()+'\n';
}

void falco::outputs::output_file::open_socket()
{
	if(socket_fd == -1) {
		socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (socket_fd == -1) {
			throw falco_exception("failed to open the socket");
		}

		// 设置Unix域套接字地址
		struct sockaddr_un addr;
		addr.sun_family = AF_UNIX;
		strncpy(addr.sun_path, "/run/falco/falco.sock", sizeof(addr.sun_path) - 1);

		// 连接Unix域套接字
		if (connect(socket_fd, (struct ::sockaddr *) &addr, sizeof(addr)) == -1) {
			close(socket_fd);
			socket_fd = -1;
			throw falco_exception("failed to connect the socket sock file");
		}
	}
}

void falco::outputs::output_file::output(const message *msg)
{
	open_socket();
	std::string msg_str = serialize_message(msg);
	if (send(socket_fd, msg_str.c_str(), msg_str.size(), 0) == -1)
	{
		// 发送失败，可能是连接断开了
		close(socket_fd);
		throw falco_exception("disconnect");
	}

	if(m_oc.options["keep_alive"] != "true")
	{
		cleanup();
	}
}

void falco::outputs::output_file::cleanup()
{
	if(socket_fd != -1)
	{
		close(socket_fd);
	}
}


void falco::outputs::output_file::reopen()
{
	cleanup();
	open_socket();
}


//
//
//void falco::outputs::output_file::open_file()
//{
//    if(!m_buffered)
//    {
//        m_outfile.rdbuf()->pubsetbuf(0, 0);
//    }
//    if(!m_outfile.is_open())
//    {
//        m_outfile.open(m_oc.options["filename"], fstream::app);
//        if (m_outfile.fail())
//        {
//            throw falco_exception("failed to open output file " + m_oc.options["filename"]);
//        }
//    }
//}
//
//void falco::outputs::output_file::output(const message *msg)
//{
//    open_file();
//    m_outfile << msg->msg + "\n";
//
//    if(m_oc.options["keep_alive"] != "true")
//    {
//        cleanup();
//    }
//}
//
//void falco::outputs::output_file::cleanup()
//{
//    if(m_outfile.is_open())
//    {
//        m_outfile.close();
//    }
//}
//
//void falco::outputs::output_file::reopen()
//{
//    cleanup();
//    open_file();
//}
