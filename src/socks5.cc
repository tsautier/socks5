#include "global.h"
#include "tools.h"
#include "config.h"
#include "lock.h"
#include "counter.h"
#include "userlist.h"
#include "sslcompat.h"

// some dummy objects to use tools.h
CConfig config;
CLock sock_lock,config_lock;
CCounter monthcounter,weekcounter,daycounter;
int use_blowconf = 1;
string bk = "";
string conffile;
int listen_sock = -1;
string old_oidentd; // save old oidentd.conf
CUserList userlist;

pthread_attr_t threadattr;
SSL_CTX *sslctx = NULL;

// NOTE: OpenSSL 1.1.0 made libcrypto thread-safe on its own and reduced
// CRYPTO_set_locking_callback(), CRYPTO_set_id_callback() and the dynlock
// callbacks to empty macros. The manual pthread mutex plumbing that used to
// live here was therefore dead code under OpenSSL 3 and has been removed.

int ssl_setup()
{
	sslctx = NULL;
	
	if (RAND_status()) { debugmsg("-SYSTEM-","RAND_status ok"); }
	else { cout << "RAND_status not ok\n"; return 0; }
	sslctx = SSL_CTX_new(TLS_server_method());
	if (sslctx == NULL)
	{
		debugmsg("-SYSTEM-", "error creating ctx");		
		return 0;
	}
		
	SSL_CTX_set_default_verify_paths(sslctx);
	SSL_CTX_set_options(sslctx,SSL_OP_ALL | SSL_OP_NO_COMPRESSION |
	                           SSL_OP_CIPHER_SERVER_PREFERENCE);
	// TLS 1.0 and 1.1 are long dead; refuse them outright.
	SSL_CTX_set_min_proto_version(sslctx, TLS1_2_VERSION);
	SSL_CTX_set_mode(sslctx,SSL_MODE_AUTO_RETRY);
		
	debugmsg("-SYSTEM-", "try to load cert file");
	if (SSL_CTX_use_certificate_chain_file(sslctx,config.ssl_cert.c_str()) <= 0)
	{	
		
		debugmsg("-SYSTEM-", "error loading cert file!");
		return 0;
	}
	else 
	{
		debugmsg("-SYSTEM-", "try to load private key");
		if (SSL_CTX_use_PrivateKey_file(sslctx, config.ssl_cert.c_str(), SSL_FILETYPE_PEM) <=0 )
		{	
			debugmsg("-SYSTEM-", "error loading private key!");
			return 0;
		}		
	}
	debugmsg("-SYSTEM-", "enabling automatic DH parameters");
	SSL_CTX_set_dh_auto(sslctx, 1);

    debugmsg("-SYSTEM-", "try to check private key");
	if ( !SSL_CTX_check_private_key(sslctx))
	{		
		debugmsg("-SYSTEM-", "key invalid");
		return 0;
	}
	
	SSL_CTX_set_session_cache_mode(sslctx,SSL_SESS_CACHE_OFF);
	
	return 1;
}

class CIdentThread
{
public:
	pthread_t tid;
	friend void *identthread(void *pData);
	void thread(string oldoident)
	{								
		sleep(config.oidentdelay);
		if(config.oidentdelay > 0)
		{
			debugmsg("-SYSTEM-","try to restore old .oident.conf");
			ofstream oidentfile(config.oidentpath.c_str(),ios::out | ios::trunc);
			if(oidentfile)
			{
				oidentfile << oldoident;
				oidentfile.flush();
				oidentfile.close();
			}
			else
			{
				debugmsg("-SYSTEM-","error restoring .oident.conf");
			}
		}
				
	}
};

void *identthread(void* pData)
{
	debugmsg("IDENTTHREAD","Starting ident thread");
	CIdentThread* t = (CIdentThread*)pData;
	t->thread(old_oidentd);
	delete t;
	debugmsg("IDENTTHREAD","Ending ident thread");
	return NULL;
}

class CSockThread
{
public: 

	void oident_thread(void *)
	{
	}

	CSockThread(int sock,string clip,int clport)
	{
		tmp_sock = sock;
		server_sock = -1;
		bind_sock = -1;
		cport = clport;
		cip = clip;
		ssl = NULL;
		buffer = new char[config.buffersize];
	}

	~CSockThread()
	{
		debugmsg("CSockThread","destructor start");

		if(ssl != NULL)
		{
			SSL_shutdown(ssl);
		}

		Close(tmp_sock,"");
		Close(server_sock,"");
		Close(bind_sock,"");

		if (ssl != NULL) 
		{ 			
			SSL_free(ssl); 
			ssl = NULL; 
		}

		delete [] buffer;
		debugmsg("CSockThread","destructor End");		
	}
	
	friend void *makethread(void *pData);

	pthread_t tid; // thread id

private:

	char *buffer;
	int tmp_sock;
	int server_sock;
	int bind_sock;
	int cport; // port from client - for ident request
	string cip; // ip from client - for ident request
	SSL *ssl;
	int shouldquit;

	void mainloop(void)
	{
		
		if(config.use_ssl)
		{
			shouldquit = 0;
			if(!SslAccept(tmp_sock,&ssl,&sslctx,shouldquit))
			{
				debugmsg("-SYSTEM-", "[client thread] ssl accept from client failed",errno);
				return;
			}
		}
			CUserEntry entry;
			string tmp;
			string user_ident = "*";
			if(!config.no_ident_check)
			{
				if(!Ident(cip,cport,config.listen_port,config.listen_ip,user_ident,config.ident_timeout))
				{
					user_ident = "*";
				}
			}
			
			memset(buffer,'\0',config.buffersize);
			
			fd_set data_readfds;

			for(int i=0; i < config.read_write_timeout * 2;i++)
			{
				FD_ZERO(&data_readfds);
				FD_SET(tmp_sock,&data_readfds);
				
				struct timeval tv;
				tv.tv_sec = 0;
				tv.tv_usec = 500000;
				
				if (select(tmp_sock+1, &data_readfds, NULL, NULL, &tv) > 1)
				{					
					break;
				}
				
			}
			int rc;
			if (FD_ISSET(tmp_sock, &data_readfds))
			{
				if(!DataRead(tmp_sock,buffer,rc,ssl,0,0))
				{					
					debugmsg("-SYSTEM-","data read failed");
					return;
				}
				if(rc >= 3 && rc <= 257)
				{
					debugmsg("-SYSTEM-",">= 3 bytes read - fine");
					if(buffer[0] == 5)
					{
						debugmsg("-SYSTEM-","protocol is 5 - fine");
					}
					else
					{
						debugmsg("-SYSTEM-","protocol is not 5");
						buffer[0] = 5; // protocol version
						buffer[1] = 255; // method user/pass
						DataWrite(tmp_sock,buffer,2,ssl);						
						return;
					}
					if(buffer[1] >= 1)
					{
						debugmsg("-SYSTEM-","number of methods >= 1 - fine");
					}
					else
					{
						debugmsg("-SYSTEM-","number of methods < 1");
						buffer[0] = 5; // protocol version
						buffer[1] = 255; // no acceptable method
						DataWrite(tmp_sock,buffer,2,ssl);
						return;
					}
					if(buffer[1] +2 != rc)
					{
						debugmsg("-SYSTEM-","number of methods does not match read methods");
						buffer[0] = 5; // protocol version
						buffer[1] = 255; // no acceptable method
						DataWrite(tmp_sock,buffer,2,ssl);
						return;
					}
					bool right_method = false;
					for(int i=0;i < buffer[1];i++)
					{
						if(buffer[i+2] == 2) right_method = true;
					}
					if(right_method)
					{
						debugmsg("-SYSTEM-","method is user/pass - fine");
					}
					else
					{
						debugmsg("-SYSTEM-","wrong method requested");
						buffer[0] = 5; // protocol version
						buffer[1] = 255; // no acceptable method
						DataWrite(tmp_sock,buffer,2,ssl);
						return;
					}

				}
				else
				{
					debugmsg("-SYSTEM-","wrong number of bytes read");
					buffer[0] = 5; // protocol version
					buffer[1] = 255; // no acceptable method
					DataWrite(tmp_sock,buffer,2,ssl);
					return;
				}
			}
			else
			{
				debugmsg("-SYSTEM-","fd_isset error");
				return;
			}
			buffer[0] = 5; // protocol version
			buffer[1] = 2; // method user/pass
			if(!DataWrite(tmp_sock,buffer,2,ssl))
			{
				debugmsg("-SYSTEM-","error writing to client");
				return;
			}
			for(int i=0; i < config.read_write_timeout * 2;i++)
			{
				FD_ZERO(&data_readfds);
				FD_SET(tmp_sock,&data_readfds);
				
				struct timeval tv;
				tv.tv_sec = 0;
				tv.tv_usec = 500000;
				
				if (select(tmp_sock+1, &data_readfds, NULL, NULL, &tv) > 1)
				{					
					break;
				}
				
			}
			
			if (FD_ISSET(tmp_sock, &data_readfds))
			{
				if(!DataRead(tmp_sock,buffer,rc,ssl,0,0))
				{					
					debugmsg("-SYSTEM-","data read failed");
					return;
				}
				if(rc < 4)
				{
					debugmsg("-SYSTEM-","wrong length");
					buffer[0] = 1; // protocol version
					buffer[1] = 1; // failure
					DataWrite(tmp_sock,buffer,2,ssl);
					return;
				}
				int namel,passl;
				namel = 0;
				passl = 0;
				if(buffer[0] == 1)
				{
					debugmsg("-SYSTEM-","sub protocol is 1 - fine");
				}
				else
				{
					debugmsg("-SYSTEM-","wrong protocol");
					buffer[0] = 1; // protocol version
					buffer[1] = 1; // failure
					DataWrite(tmp_sock,buffer,2,ssl);
					return;
				}
				namel = buffer[1];
				string username;
				if(namel + 2 >= rc)
				{
					debugmsg("-SYSTEM-","wrong username length");
					buffer[0] = 1; // protocol version
					buffer[1] = 1; // failure
					DataWrite(tmp_sock,buffer,2,ssl);
					return;
				}
				for(int i=0;i < namel;i++)
				{
					username += buffer[i+2];
				}
				passl = buffer[2+namel];
				if(namel + 3 + passl > rc)
				{
					debugmsg("-SYSTEM-","wrong pass length");
					buffer[0] = 1; // protocol version
					buffer[1] = 1; // failure
					DataWrite(tmp_sock,buffer,2,ssl);
					return;
				}
				string pass;
				for(int i=0;i < passl;i++)
				{
					pass += buffer[i+3+namel];
				}			
				if(!userlist.CheckPass(username, pass, entry))
				{
					debugmsg("-SYSTEM-","wrong user/pass");
					debugmsg("-SYSTEM-","name is: '" + username + "' pass is: '" + pass + "'");
					buffer[0] = 1; // protocol version
					buffer[1] = 1; // failure
					DataWrite(tmp_sock,buffer,2,ssl);
					return;
				}
				// ip check here
				if(!userlist.CheckUserHost(cip,entry))
				{
					debugmsg("-SYSTEM-","wrong userip");					
					buffer[0] = 1; // protocol version
					buffer[1] = 1; // failure
					DataWrite(tmp_sock,buffer,2,ssl);
					return;
				}
				if(!config.no_ident_check)
				{
					if(!userlist.CheckIdent(username,user_ident))
					{
						debugmsg("-SYSTEM-","wrong ident");
						debugmsg("-SYSTEM-","ident is: '" + user_ident + "'");
						buffer[0] = 1; // protocol version
						buffer[1] = 1; // failure
						DataWrite(tmp_sock,buffer,2,ssl);
						return;
					}
				}
				//everything ok
				buffer[0] = 1; // protocol version
				buffer[1] = 0; // ok
				if(!DataWrite(tmp_sock,buffer,2,ssl))
				{
					debugmsg("-SYSTEM-","error writing to client");
					return;
				}
				
				for(int i=0; i < config.read_write_timeout * 2;i++)
				{
					FD_ZERO(&data_readfds);
					FD_SET(tmp_sock,&data_readfds);
					
					struct timeval tv;
					tv.tv_sec = 0;
					tv.tv_usec = 500000;
					
					if (select(tmp_sock+1, &data_readfds, NULL, NULL, &tv) > 1)
					{					
						break;
					}
					
				}
				
				if (FD_ISSET(tmp_sock, &data_readfds))
				{
					if(!DataRead(tmp_sock,buffer,rc,ssl,0,0))
					{					
						debugmsg("-SYSTEM-","data read failed");
						return;
					}
					if(rc < 10)
					{
						debugmsg("-SYSTEM-","illegal length");
						buffer[0] = 5; // protocol version
						buffer[1] = 1; // general SOCKS server failure
						DataWrite(tmp_sock,buffer,2,ssl);						
						return;
					}
					if(buffer[0] == 5)
					{
						debugmsg("-SYSTEM-","protocol is 5 - fine");
					}
					else
					{
						debugmsg("-SYSTEM-","protocol is not 5");
						buffer[0] = 5; // protocol version
						buffer[1] = 1; // general SOCKS server failure
						DataWrite(tmp_sock,buffer,2,ssl);						
						return;
					}

					string method = ""; // connect or bind

					if(buffer[1] == 1)
					{
						debugmsg("-SYSTEM-","cmd is connect - fine");
						method = "connect";
					}
					else if(buffer[1] == 2)
					{
						debugmsg("-SYSTEM-","cmd is bind - fine");
						method = "bind";
					}
					else
					{
						debugmsg("-SYSTEM-","unsupported command");
						buffer[0] = 5; // protocol version
						buffer[1] = 1; // general SOCKS server failure
						DataWrite(tmp_sock,buffer,2,ssl);						
						return;
					}
					if(buffer[2] == 0)
					{
						debugmsg("-SYSTEM-","reserverd is 0 - fine");
					}
					else
					{
						debugmsg("-SYSTEM-","reserverd != 0");
						buffer[0] = 5; // protocol version
						buffer[1] = 1; // general SOCKS server failure
						DataWrite(tmp_sock,buffer,2,ssl);						
						return;
					}
					if(buffer[3] == 1)
					{
						debugmsg("-SYSTEM-","atype is ipv4 - fine");
					}
					else if(buffer[3] == 3)
					{
						debugmsg("-SYSTEM-","atype is domainname - fine");
					}
					else
					{
						debugmsg("-SYSTEM-","atype != 1");
						buffer[0] = 5; // protocol version
						buffer[1] = 8; // Address type not supported
						DataWrite(tmp_sock,buffer,2,ssl);						
						return;
					}
					struct sockaddr_in listenadr;
					
					// for bind mode
					int bindport = 0;
					int shouldquit = 0;
					string clientip = "";
					int clientport = 0;
					
						
					// modify oident.conf file to allow spoofing
					if(config.oidentpath != "" && entry.oident == 1)
					{						
						debugmsg("-SYSTEM-","trying to modify .oident.conf");
						ofstream oidentfile(config.oidentpath.c_str(),ios::out | ios::trunc);
						if(oidentfile)
						{
							oidentfile << "global {\n";
							if(entry.oidentident == "")
							{
								oidentfile << "reply \"" + user_ident + "\"\n";
							}
							else
							{
								oidentfile << "reply \"" + entry.oidentident + "\"\n";
							}
							oidentfile << "}\n";
							oidentfile.flush();
							oidentfile.close();
						}
						else
						{
							debugmsg("-SYSTEM-","error modifying .oident.conf");
						}
					}

					if(method == "connect")
					{
						string ip;
						struct sockaddr_in myaddr;
						memset(&myaddr,0,sizeof(myaddr));
						myaddr.sin_family = AF_INET;
						if(buffer[3] != 1 && buffer[3] != 3)
						{
							// RFC 1928: 0x08 = address type not supported.
							// ATYP 4 (IPv6) lands here.
							debugmsg("-SYSTEM-","unsupported address type");
							buffer[0] = 5; // protocol version
							buffer[1] = 8; // address type not supported
							DataWrite(tmp_sock,buffer,2,ssl);
							return;
						}
						if(buffer[3] == 1)
						{
							memcpy(&myaddr.sin_addr.s_addr,buffer+4,4);
							ip = inet_ntoa(myaddr.sin_addr);
							memcpy(&myaddr.sin_port,buffer+8,2);
						}
						else if(buffer[3] == 3)
						{
							// first check if length is ok
							if(rc < buffer[4] + 6)
							{
								debugmsg("-SYSTEM-","illegal domain length");
								buffer[0] = 5; // protocol version
								buffer[1] = 1; // general SOCKS server failure
								DataWrite(tmp_sock,buffer,2,ssl);	
								return;
							}
							memcpy(&myaddr.sin_port,buffer+buffer[4]+5,2);
							for(int i=0; i < buffer[4];i++)
							{
								ip += (char)buffer[5+i];								
							}
						}
						
						myaddr.sin_port = ntohs(myaddr.sin_port);
										
						if(!GetSock(server_sock))
						{
							debugmsg("-SYSTEM-","error getting socket");
							buffer[0] = 5; // protocol version
							buffer[1] = 1; // general SOCKS server failure
							DataWrite(tmp_sock,buffer,2,ssl);	
							return;
						}
						if (config.connect_ip != "")
						{
							debugmsg("-SYSTEM-","try to set connect ip for connect");
							
							if(!Bind(server_sock,config.connect_ip,0))
							{
								debugmsg("-SYSTEM-","connect ip - could not bind",errno);
								buffer[0] = 5; // protocol version
								buffer[1] = 1; // general SOCKS server failure
								DataWrite(tmp_sock,buffer,2,ssl);	
								return;
							}
						}
						// check if ip is allowed (allowed list)
						if(!userlist.CheckAllowedHost(ip,entry))
						{
							debugmsg("-SYSTEM-","allow list not empty - ip not allwoed",errno);
							buffer[0] = 5; // protocol version
							buffer[1] = 1; // general SOCKS server failure
							DataWrite(tmp_sock,buffer,2,ssl);	
							return;
						}

						// check if ip is allowed (banned list)
						if(userlist.CheckBannedHost(ip,entry))
						{
							debugmsg("-SYSTEM-","ip is in banned list",errno);
							buffer[0] = 5; // protocol version
							buffer[1] = 1; // general SOCKS server failure
							DataWrite(tmp_sock,buffer,2,ssl);	
							return;
						}
						
						
						
						int shouldquit = 0;						
						if(entry.socksip == "")
						{
							if(!Connect(server_sock,ip,myaddr.sin_port,config.connect_timeout,shouldquit))
							{
								debugmsg("-SYSTEM-","connect error");
								buffer[0] = 5; // protocol version
								buffer[1] = 5; // general SOCKS server failure
								DataWrite(tmp_sock,buffer,2,ssl);	
								return;
							}
						}
						else
						{
							if(!Connect5(server_sock,ip,myaddr.sin_port, entry.socksip, entry.socksport, entry.socksuser, entry.sockspass, config.connect_timeout,shouldquit))
							{
								debugmsg("-SYSTEM-","connect error");
								buffer[0] = 5; // protocol version
								buffer[1] = 5; // general SOCKS server failure
								DataWrite(tmp_sock,buffer,2,ssl);	
								return;
							}
						}
					}
					else if(method == "bind")
					{						
						bindport = random_range(config.bind_port_start, config.bind_port_end);
						//cout << "bindport: " << bindport << "\n";
						if(!GetSock(bind_sock))
						{
							debugmsg("-SYSTEM-","error getting socket");
							buffer[0] = 5; // protocol version
							buffer[1] = 1; // general SOCKS server failure
							DataWrite(tmp_sock,buffer,2,ssl);	
							return;
						}
						
						debugmsg("-SYSTEM-","try to set ip for listen");
						
						if(!Bind(bind_sock,config.listen_ip,bindport))
						{
							debugmsg("-SYSTEM-","connect ip - could not bind",errno);
							buffer[0] = 5; // protocol version
							buffer[1] = 1; // general SOCKS server failure
							DataWrite(tmp_sock,buffer,2,ssl);	
							return;
						}						
						
						if (listen(bind_sock, config.pending) == -1)
						{
							debugmsg("-SYSTEM-","Unable to listen!");							
							return;
						}
						
					}
					else
					{
						debugmsg("-SYSTEM-","connect error");
						buffer[0] = 5; // protocol version
						buffer[1] = 5; // general SOCKS server failure
						DataWrite(tmp_sock,buffer,2,ssl);	
						return;
					}
					
					string tmpip;
					if (config.listen_ip != "") 
					{ 
						tmpip = config.listen_ip; 
					}
					else
					{
						
						struct ifreq ifa;
						struct sockaddr_in *i;
						memset(&ifa,0,sizeof( struct ifreq ) );
						strcpy(ifa.ifr_name,config.listen_interface.c_str());
						
						int rc = ioctl(listen_sock, SIOCGIFADDR, &ifa);
						
						if(rc != -1)
						{
							i = (struct sockaddr_in*)&ifa.ifr_addr;
							tmpip = inet_ntoa(i->sin_addr);
						}
						else
						{
							tmpip = "0.0.0.0";
							debugmsg("-SYSTEM-","[getlistenip] ioctl error",errno);
						}						
					}

					if(method == "connect")
					{
						
						buffer[0] = 5; // protocol version
						buffer[1] = 0; // succeeded
						buffer[2] = 0;
						buffer[3] = 1;
						inet_aton(tmpip.c_str(),&listenadr.sin_addr);
						listenadr.sin_port = htons(config.listen_port); 
						memcpy(buffer+8,&listenadr.sin_port,2);
						memcpy(buffer+4,&listenadr.sin_addr,4);
						if(!DataWrite(tmp_sock,buffer,10,ssl))
						{
							debugmsg("-SYSTEM-","error writing to client");
							return;
						}
					}
					else if(method == "bind")
					{						

						buffer[0] = 5; // protocol version
						buffer[1] = 0; // succeeded
						buffer[2] = 0;
						buffer[3] = 1;
						inet_aton(tmpip.c_str(),&listenadr.sin_addr);
						listenadr.sin_port = htons(bindport); 
						memcpy(buffer+8,&listenadr.sin_port,2);
						memcpy(buffer+4,&listenadr.sin_addr,4);
						
						if(!DataWrite(tmp_sock,buffer,10,ssl))
						{
							debugmsg("-SYSTEM-","error writing to client");
							return;
						}

						if (!Accept(bind_sock,server_sock,clientip,clientport,config.connect_timeout,shouldquit))
						{
							debugmsg("-SYSTEM-","accept failed",errno);
							buffer[0] = 5; // protocol version
							buffer[1] = 1; // general SOCKS server failure
							DataWrite(tmp_sock,buffer,2,ssl);	
							return;
						}
						cout << "bind_sock " << bind_sock << "\n";
						cout << "server_sock " << server_sock << "\n";

						debugmsg("-SYSTEM-","accept done",errno);
						buffer[0] = 5; // protocol version
						buffer[1] = 0; // succeeded
						buffer[2] = 0;
						buffer[3] = 1;
						inet_aton(tmpip.c_str(),&listenadr.sin_addr);
						listenadr.sin_port = htons(bindport); 
						memcpy(buffer+8,&listenadr.sin_port,2);
						memcpy(buffer+4,&listenadr.sin_addr,4);
						Close(bind_sock,"");
						if(!DataWrite(tmp_sock,buffer,10,ssl))
						{
							debugmsg("-SYSTEM-","error writing to client");
							return;
						}
					}
					
					// restore old oidentd.conf
					if(config.oidentpath != "" && entry.oident == 1)
					{
						CIdentThread *thread = new CIdentThread;
						pthread_create(&thread->tid,&threadattr,identthread,thread);
					}

					while (1)
					{
						FD_ZERO(&data_readfds);
						FD_SET(tmp_sock, &data_readfds);
						FD_SET(server_sock, &data_readfds);
						int tmpsock;
						if (tmp_sock > server_sock)
						{
							tmpsock = tmp_sock;
						}
						else
						{
							tmpsock = server_sock;
						}
						
						
						if (select(tmpsock+1, &data_readfds, NULL, NULL, NULL) <= 0)
						{
							debugmsg("-SYSTEM-", "select error!",errno);
							return;
						}
																	
						// just to make sure - should not happen
						if(tmp_sock < 0 || server_sock < 0) return;
						
						// read from site - send to client
						if (FD_ISSET(server_sock, &data_readfds))
						{
							memset(buffer,'\0',1);
					
							int rc;
							if(!DataRead(server_sock,buffer,rc,NULL,0,0))
							{					
								return;
							}
							
							if(!DataWrite(tmp_sock,buffer,rc,ssl))
							{					
								return;
							}
						}
						// read from client - send to site
						else if (FD_ISSET(tmp_sock, &data_readfds))
						{
							memset(buffer,'\0',1);

							int rc;
							if(!DataRead(tmp_sock,buffer,rc,ssl,0,0))
							{					
								return;
							}
							
							if(!DataWrite(server_sock,buffer,rc,NULL))
							{				
								return;
							}
						}
						else
						{
							debugmsg("-SYSTEM-","fd_isset error",errno);
							return;
						}
					}
				}
			}
			
	}

};

void *makethread(void* pData)
{
	debugmsg("-SYSTEM-","[makethread] start");
	CSockThread *st = (CSockThread*)pData;
	try
	{
		st->mainloop();
	}
	catch(...)
	{
		debugmsg("--THREAD EXEPTION--","");
	}
	debugmsg("-SYSTEM-","[makethread] delete st");
	delete st;
	debugmsg("-SYSTEM-","[makethread] end");
	return NULL;
}



int main(int argc,char *argv[])
{	
	// Work out whether we will need Blowfish before touching the library.
	// "socks5 <conf>" is the encrypted form and needs the legacy provider;
	// "socks5 -u <conf>" is plaintext, and anything else just prints usage.
	bool need_legacy = (argc == 2);

	string crypto_err;
	if (!crypto_init(need_legacy, crypto_err))
	{
		cout << "Fatal: " << crypto_err << "\n";
		return -1;
	}

	pthread_attr_init(&threadattr);
	pthread_attr_setdetachstate(&threadattr,PTHREAD_CREATE_DETACHED);
	
	if (argc < 2 || argc > 3)
	{		
		cout << version << "\n";
		cout << "Builddate: " << builddate << "\n";
		cout << "Using " << OpenSSL_version(OPENSSL_VERSION) << "\n";
		cout << "Usage:\n\t socks5 configfile\n";
		cout << "\t or socks5 -u configfile for uncrypted conf file\n";
		return -1;
	}
	
	if (argc == 3)
	{
		string t(argv[1]);
		if (t == "-u")
		{			
			use_blowconf = 0;
		}
		else
		{
			cout << version << "\n";
			cout << "Builddate: " << builddate << "\n";
			cout << "Using " << OpenSSL_version(OPENSSL_VERSION) << "\n";
			cout << "Usage:\n\t socks5 configfile\n";
			cout << "\t or socks5 -u configfile for uncrypted conf file\n";
			return -1;
		}
	}
	if (use_blowconf == 1)
	{
		conffile = argv[1];
				
		char *k;
		k = getpass("Enter config blowfish key: ");
		bk = k;
		memset(k, 0,bk.length());
				
		if (!config.readconf(conffile,bk,1))
		{		
			return -1;
		}
	}
	else
	{
		conffile = argv[2];
		if (!config.readconf(conffile,bk,0))
		{		
			return -1;
		}
	}
	if(config.use_ssl)
	{
		if(!ssl_setup())
		{
			return -1;
		}
	}

	if((listen_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{	
		debugmsg("-SYSTEM-","Unable to create socket!");
		return -1;
	}
	
	if(!SocketOption(listen_sock,SO_REUSEADDR))
	{
		debugmsg("-SYSTEM-","setsockopt error!");
		return -1;
	}
	
	if (!Bind(listen_sock, config.listen_ip, config.listen_port))
	{
		debugmsg("-SYSTEM-","Unable to bind to port!");
		return -1;
	}	
	
	if (listen(listen_sock, config.pending) == -1)
	{
		debugmsg("-SYSTEM-","Unable to listen!");
		return -1;
	}
	
	// fork or exit
	if (!config.debug || (!config.log_to_screen && config.debug))
	{	
		debugmsg("-SYSTEM-","[main] try to run as daemon");		
		if( daemon(1,1) != 0)
		{    	
    		debugmsg("-SYSTEM-","[main] error while forking!",errno);
		}
		else
		{    	
    		debugmsg("-SYSTEM-","[main] running as daemon now");
		}
     
	}
	
	//make gethostbyname working after chroot
	//struct sockaddr_in tmpaddr = GetIp("www.glftpd.com",21);
	
	char *cwd = getcwd(NULL, 4096);
	if (config.no_chroot)
	{
		// Staying out of the chroot keeps glibc's NSS modules reachable, so
		// hostname targets still resolve. Set no_chroot=1 in the config if
		// clients need to connect to anything by name.
		debugmsg("-SYSTEM-","no_chroot set - not chrooting");
	}
	else if (chroot(cwd) != 0)
	{
		debugmsg("-SYSTEM-"," - WARNING: - Could not chroot",errno);
	}
	else
	{
		if (chdir("/") != 0)
		{
			debugmsg("-SYSTEM-"," - WARNING: - Could not chdir after chroot",errno);
		}
	}
	free(cwd);
			
	signal(SIGPIPE, SIG_IGN);
		
	int pid = getpid();
	
	ofstream pidfile(config.pidfile.c_str(), ios::out | ios::trunc);
	if (!pidfile)
	{
		debugmsg("-SYSTEM-"," - WARNING: - Error creating pid file!");		
	}
	else
	{		
		pidfile << pid << "\n";
		pidfile.close();
	}
	
	if(config.oidentpath != "")
	{
		debugmsg("-SYSTEM-","trying to modify .oident.conf");
		ifstream oidentfile(config.oidentpath.c_str(),ios::in);
		if(oidentfile)
		{
			while(oidentfile.good())
			{
				old_oidentd += oidentfile.get();
			}
			oidentfile.close();
		}
	}

	if(setuid(config.uid) < 0)
	{
		debugmsg("-SYSTEM-"," - WARNING: - Could not set uid!");				
	}

	while(1)
	{
		int tmp_sock = -1;
		string clientip;
		int clientport;
		int shouldquit = 0;
		
		if (Accept(listen_sock,tmp_sock,clientip,clientport,0,shouldquit))
		{
			if(!userlist.CheckAllIps(clientip))
			{
				debugmsg("-SYSTEM-","no user has this ip",errno);				
				Close(tmp_sock,"");
			}
			else
			{				
				CSockThread *tmp;
				tmp = new CSockThread(tmp_sock,clientip,clientport);
				if(pthread_create(&tmp->tid,&threadattr,makethread,tmp) != 0)
				{
					debugmsg("-SYSTEM-","[main] error creating thread",errno);				
				}
			}

		}
	}
}
