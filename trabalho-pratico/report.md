<img src='uminho.png' width="30%"/>

<h3 align="center">Licenciatura em Engenharia Informática <br> Trabalho prático de Segurança de Sistemas Informáticos <br> 2025/2026 </h3>

---
# Introdução

Este projeto consiste no desenvolvimento de um sistema de comunicação segura entre utilizadores com garantias de confidencialidade, integridade e autenticidade.

Para isto foi desenhada uma arquitetura do sistema e um protocolo de extenso de segurança que utiliza diferentes técnicas criptográficas na sua implementação.

---
# Arquitetura e Modelo de Segurança do Sistema

## Visão Geral

O sistema desenvolvido implementa uma plataforma de comunicação segura entre utilizadores baseada num modelo cliente-servidor, onde o servidor atua como intermediário de encaminhamento, armazenamento persistente e autoridade certificadora (Certificate Authority — CA). Apesar da existência deste servidor central, o conteúdo das mensagens trocadas entre clientes permanece protegido através de encriptação ponta-a-ponta (End-to-End Encryption — E2EE), garantindo que apenas os participantes autorizados conseguem aceder à informação transmitida.

A arquitetura do sistema combina mecanismos de criptografia assimétrica e simétrica com protocolos modernos de estabelecimento de segredos partilhados. O servidor é responsável por autenticar utilizadores, gerir certificados digitais, manter metadados persistentes do sistema e encaminhar mensagens entre clientes. Os clientes, por sua vez, são responsáveis pela geração e gestão das suas identidades criptográficas, pelo estabelecimento de sessões seguras e pela encriptação/desencriptação efetiva das mensagens.

Toda a comunicação entre clientes e servidor é inicialmente protegida através de TLS (Transport Layer Security), garantindo confidencialidade e integridade ao nível do transporte. Sobre este canal seguro, é implementado adicionalmente um protocolo de segurança próprio baseado em authenticated ephemeral-ephemeral ECDH utilizando chaves efémeras X25519 e assinaturas digitais Ed25519. Este protocolo permite aos clientes estabelecer chaves de sessão temporárias autenticadas sem que o servidor tenha acesso ao segredo derivado.

As mensagens entre utilizadores são cifradas utilizando AES-GCM com chaves de sessão derivadas através de HKDF-SHA256. A utilização de chaves efémeras e limitação do número de mensagens por sessão introduz propriedades de forward secrecy, reduzindo o impacto de uma eventual compromissão futura de chaves.

A arquitetura foi desenhada com foco simultâneo em segurança, modularidade e extensibilidade, permitindo integrar diferentes mecanismos criptográficos mantendo uma separação clara entre autenticação, gestão de identidades, estabelecimento de sessões e transmissão segura de mensagens.

## Descrição detalhada 

### Estabelecimento da ligação cliente-servidor

A comunicação entre clientes e servidor é realizada sobre TCP protegido por TLS( *Transport Layer Security* ). Esta abordagem permite garantir confidencialidade, integridade e autenticação do servidor durante a transmissão de dados através da rede.
No lado do servidor, é criado inicialmente um socket TCP responsável por escutar ligações recebidas na porta definida pela aplicação. Após a criação do socket, é configurado um contexto TLS através da biblioteca `ssl` do Python. Este contexto carrega o certificado digital e a chave privada do servidor, permitindo que o servidor se autentique perante os clientes durante o TLS handshake.

Após aceitar uma nova ligação TCP, o servidor executa o método `wrap_socket(..., server_side=True)`, convertendo a ligação TCP tradicional numa ligação TLS segura. Depois do estabelecimento do canal seguro, é criada uma nova thread dedicada ao cliente conectado, permitindo ao servidor suportar múltiplos clientes em simultâneo.

No lado do cliente, é igualmente criado um contexto TLS configurado para autenticar o servidor. O cliente carrega localmente o certificado do servidor através do método `load_verify_locations`, permitindo verificar a autenticidade do certificado apresentado durante o handshake TLS. Após a criação do socket TCP, este é encapsulado numa ligação TLS utilizando `wrap_socket()`, sendo posteriormente estabelecida a ligação ao servidor.

Depois da conclusão do TLS handshake, toda a comunicação subsequente entre cliente e servidor ocorre através do canal encriptado estabelecido. Desta forma, credenciais de autenticação, certificados, mensagens e restantes datagramas trocados ficam protegidos contra ataques de escuta e alterações maliciosas de conteúdo.

Apesar da utilização de TLS já fornecer proteção ao nível do transporte, a aplicação implementa adicionalmente encriptação ponta-a-ponta (*E2EE*) entre clientes. Assim, mesmo que o servidor intermedeie a comunicação, este não possui acesso ao conteúdo das mensagens trocadas entre utilizadores.

### Estrutura e protocolos de comunicação

Após o estabelecimento do canal TLS seguro, toda a comunicação entre clientes e servidor é realizada através de datagramas serializados em formato JSON. Esta abordagem permite definir um protocolo de aplicação simples, extensível e facilmente interpretável por ambas as partes.

Cada mensagem trocada na aplicação é representada por um objeto da classe Datagram, responsável por encapsular toda a informação necessária à operação pretendida. Os datagramas incluem um campo obrigatório `command`, que identifica o tipo de operação a executar, podendo ainda conter campos adicionais dependendo do contexto da mensagem.

A serialização é realizada através da biblioteca `json`, convertendo os objetos Python em texto JSON antes da transmissão sobre o socket TLS. Cada datagrama é terminado com o carácter `\n`, permitindo delimitar corretamente mensagens consecutivas recebidas através da stream TCP.

A conversão do datagrama para um formato transmissível é realizada através do método `encode()`, que serializa o objeto para JSON e produz a sequência de bytes enviada através do socket.

No lado recetor, os dados recebidos são reconstruídos através do método `decode()`, que interpreta o JSON recebido e recria o objeto `Datagram` correspondente.

A utilização de uma estrutura de datagramas comum simplifica significativamente o processamento das mensagens, permitindo ao servidor e aos clientes identificar rapidamente a operação pretendida e os respetivos parâmetros associados.

### Autenticação de um cliente

Após o estabelecimento da ligação TLS segura entre cliente e servidor, inicia-se o processo de autenticação do utilizador. Este mecanismo permite simultaneamente autenticar utilizadores já existentes e registar automaticamente novos utilizadores no sistema.

O processo inicia-se quando o servidor envia ao cliente um datagrama do tipo `request_username()`, solicitando as credenciais de autenticação. O cliente recolhe interativamente o nome de utilizador e a palavra-passe introduzidos pelo utilizador.

Este conteúdo é posteriormente enviado ao servidor através de um datagrama `login()`. No lado do servidor, o datagrama recebido é descodificado e o conteúdo JSON é interpretado para extrair o nome de utilizador e a palavra-passe submetidos. Antes de autenticar o utilizador, o servidor verifica se já existe uma sessão ativa associada ao mesmo nome de utilizador. De seguida, se o utilizador já existe na base de dados persistente, o servidor valida a password recebida através da função `verify_password`. As palavras-passe nunca são armazenadas em texto simples. Durante o registo inicial de um utilizador, o servidor aplica um mecanismo de derivação criptográfica baseado em PBKDF2-HMAC-SHA256 com salt aleatório e 100 000 iterações. O resultado derivado é armazenado juntamente com o salt correspondente. Durante a autenticação, o servidor recupera o salt armazenado e executa novamente o algoritmo PBKDF2 sobre a password recebida. O resultado obtido é comparado com o valor previamente armazenado.

Esta abordagem garante que o servidor nunca persiste passwords em formato legível, reduzindo significativamente o impacto de uma eventual compromissão da base de dados de utilizadores.

Caso o nome de utilizador ainda não exista, o servidor procede automaticamente ao registo do novo utilizador, armazenando o hash derivado da password.

Após autenticação bem-sucedida, o servidor adiciona o utilizador à lista de clientes ativos e envia um datagrama `login_ok()`, permitindo ao cliente iniciar operações normais na aplicação.

Ao receber este datagrama de confirmação, o cliente vai inicializar determinadas operações associadas ao modelo de segurança e a features do sistema que vão ser explicadas melhor nos próximos pontos. 

### Gestão de identidades de certificados

Após a autenticação bem-sucedida do utilizador, cada cliente estabelece uma identidade criptográfica persistente baseada em criptografia assimétrica.

Cada cliente possui um par de chaves Ed25519 persistente, utilizado-o para autenticação criptográfica e assinaturas digitais.
Após o login, o cliente carrega (ou gera pela primeira vez) o seu par de identidade através do método `persistance_functions.load_or_create_identity_keypair()`.

A chave privada permanece exclusivamente armazenada no cliente, enquanto a chave pública é enviada ao servidor para certificação através de um datagrama `register_key()`.
A chave pública é convertida para bytes e codificada em Base64 para facilitar a serialização em JSON

O servidor atua como uma autoridade certificadora (CA — Certificate Authority), responsável por associar identidades de utilizadores às respetivas chaves públicas. Durante a inicialização do servidor, é carregado (ou criado) um par de chaves da CA através do método `persistance_functions.load_or_create_ca()`.

A chave pública da CA é exportada e distribuída aos clientes.

Desta forma, todos os clientes passam a possuir uma âncora de confiança comum utilizada para validar certificados emitidos pelo servidor.

Quando o servidor recebe um pedido `register_key()`, cria um certificado digital simples caso este ainda não tenha sido criado para o utilizador, contendo:

- o nome do utilizador
- a chave pública do utilizador
- uma assinatura digital da CA

O servidor constrói os dados a assinar concatenando o nome do utilizador com a chave pública. A assinatura é então produzida utilizando a chave privada da CA para assinar esses dados.

O certificado do utilizador é registado, ou seja persistido, no servidor e poderá ser distribuído a outros clientes durante o estabelecimento de sessões seguras E2E.

### Considerações das valorizações no sistema

A implementação de determinadas valorizações tiveram consequências na modelaçao da arquitetura e fluxo do sistema. As valorizações implementadas foram:
 - Mensagens Offline (Servidor guarda mensagens que utilizador tenta enviar para utilizadores que estavam offline no momento do envio. Quando estes voltam a ficar online, mensagens serão devidamente entregues)
 - CA/Certificados (Servidor funciona como Certificate Authority e emite certificados que comprovam identidade de utilizadores)
 - Mensagens de Grupo (Distribuição de mensagens de acesso exclusivo a um determinado conjunto de utilizadores)
 - Forward Secrecy (Utilização de chaves efémeras/temporárias. Se uma chave for comprometida, não afeta mensagens antigas)

Estas valorizações serão mencionadas e o seu envolvimento será esclarecido em detalhe na explicação do fluxo do sistema.

### Operações de um utilizador

Após um utilizador ter-se autenticado e ter sido automaticamente certificado no sistema, tem uma variedade de funcionalidades a seu dispor.

A funcionalidade mais básica do sistema é a de enviar uma mensagem a outro utilizador através do comando `/msg`. Para isto o utilizador deve primeiro adicionar o utilizador à sua lista de contactos através do comando `/add`, podendo remover utilizadores da lista com `/remove`. O servidor mantém os metadados dos seus utilizadores armazenados, nomeadamente o nome de utilizador, os seus contactos e o hash da password. Note-se que esta lista não têm qualquer interferência na segurança do sistema é apenas um requisito funcional do programa.

Para listar os seus contactos pode utilizar `/list_contacts`.

As operações de grupos envolvem:
- criar um grupo com `/add_group`
- adicionar um utilizador ao grupo com `/group_invite`
- mandar uma mensagem para um grupo com `/group_msg`
- sair de um grupo com `/leave_group`
- listar todos grupos a que pertence com `/list_groups`

### Fluxo de operações e protocolo de segurança

O protocolo de segurança utilizado baseia-se num esquema *authenticated ephemeral-ephemeral ECDH(Elliptic-Curve Diffie-Hellman)*. 

A base de comunicação entre dois clientes é o estabelecimento de um segredo partilhado (chave de sessão) entre os dois de forma assimétrica, para ser posteriormente utilizado para encriptar comunicação entre os dois simétricamente. 
A criptografia assimétrica permite autenticar identidades e estabelecer segredos partilhados sem transmissão direta da chave.
A criptografia simétrica possui um custo computacional significativamente inferior, sendo mais eficiente para cifrar grandes volumes de mensagens.

Este é o processo:

1. Para um cliente mandar uma mensagem para outro cliente terá que criar uma sessão com este. Para isto o cliente envia um pedido de sessão com o determinado cliente para o servidor através do comando `/session`. Será então enviado pelo canal seguro o datagrama `request_session()`.

2. Após receber o pedido, o servidor irá confirmar da existência do cliente recetor e que de facto este encontra-se online, e envia para o recetor o certificado do enviador, e para o enviador o certificado do recetor. Lembrar que o certificado envolve o nome do utilizador, a chave identidade pública do utilizador e a assinatura digital do servidor/CA. O datagrama utilizado pelo servidor é `session_response()`.

3. Cada cliente ao receber o certificado utiliza a chave identidade pública do CA para verificar a assinatura do certificado, comprovando efetivamente que de facto a chave identidade pública do outro cliente é garantidamente desse cliente com raíz na confiança que o cliente tem no CA.

4. Após verificar assinatura, cada cliente gera um par de chaves efémeras X25519 (uma implementação moderna de ECDH, baseada na curva elíptica Curve25519).

5. Devido à assincronidade deste processo, os clientes carregam as informações do outro cliente em que confiam numa lista. As informações guardadas nesta lista pessoal de confiança são o par efémero (chave privada e pública) e a chave identidade pública que confia ser do utilizador. 

6. Cada cliente após colocar o outro na lista de confiança, cria um concatenação do seu nome de utilizador e a sua chave efémera pública e assina-a com a sua chave identidade privada. Depois forma um payload com o seu nome de utilizador, chave efémera pública e assinatura digital e envia-a para o servidor através do datagram `send_session_ephemeral()` para ser reencaminhada para o outro cliente pelo servidor através do datagrama `session_ephemeral()`.

7. Ao receber o respetivo payload enviado pelo outro cliente, cada cliente procura na lista de confiança pelo o outro. Obtendo a chave identidade pública do outro cliente, verificam a assinatura digital que tinha sido anteriormente assinada pela chave identidade privada do outro cliente. Ou seja, passando a verificação, obtém um comprovativo que a chave efémera pública de facto pertence ao respetivo outro cliente. A confiança da chave pública efémera é baseada na confiança que temos num utilizador que é baseada na confiança que temos no CA, que neste caso é o servidor. O servidor é a raiz de confiança e autenticidade em todo o sistema.

8. Após ter confiança na chave efémera pública do outro cliente, deriva-se um segredo através das chaves efémeras, onde cada cliente utiliza a sua chave efémera privada e a chave efémera pública do outro cliente. Depois deriva-se a partir desse segredo uma chave de sessão dos dois clientes através de um KDF baseado em HKDF com SHA-256 para formar uma chave AES válida. Essa chave de sessão é guardada no cliente para utilização. A sua utilização é efémera portanto contador é inicializado neste momento. Após um limite `n_limit`, a chave será apagada e os clientes terão de criar uma nova sessão entre os dois dando um grau flexível de *forward secrecy* ao sistema.


Tendo uma sessão válida com o cliente recetor, um cliente pode-lhe enviar mensagens.

Este é o processo: 

1. Para um cliente mandar uma mensagem para outro cliente utiliza o comando `/msg`.

2. Utilizando este comando, verifica se tem sessão com o outro cliente e se o limite de mensagens for atingido a chave é apagada e uma nova sessão terá de ser criada.

3. Se o limite não for atingido, o contador é incrementado e a mensagem é encriptada utilizando AES-GCM (*Advanced Encryption Standard - Galois/Counter Mode*) com a chave de sessão previamente derivada através do protocolo ECDH. Para cada mensagem é gerado um nonce aleatório de 96 bits. Este nonce é utilizado em conjunto com a chave de sessão para encriptar a mensagem. O nonce é utilizado no AES-GCM para garantir que duas mensagens encriptadas com a mesma chave produzam ciphertexts diferentes e seguros, prevenindo atacantes de descubrir relações entre mensagens. O resultado da operação corresponde ao ciphertext autenticado produzido pelo AES-GCM, contendo também uma authentication tag utilizada posteriormente na verificação de integridade da mensagem.. O nonce é concatenado ao ciphertext e o resultado dessa concatenação é enviado para o servidor e reencaminhado por este, ambos através do datagrama `msg()`.

4. O recetor verifica que realmente tem uma sessão válida com o enviador, se não for o caso envia o datagrama `no_session_inform()` ao servidor que irá alertar o enviador que não tem uma sessão com o recetor.

5. Se tiver uma sessão, o nonce e o ciphertext são novamente separados, sendo depois utilizada a mesma chave de sessão para desencriptação da mensagem recebida. Durante este processo, o AES-GCM verifica automaticamente a integridade e autenticidade da mensagem através da authentication tag incluída no ciphertext. Caso o ciphertext tenha sido alterado maliciosamente ou corrompido durante a transmissão, a verificação falha e a mensagem é rejeitada.


O fluxo das mensagens de grupo segue um protocolo de segurança adaptado. No entanto nesse caso, o criador do grupo cria uma chave secreta, que irá ser partilhada aqueles que entrem no grupo. O criador do grupo é administrador deste ao nível das funcionalidade do programa e apenas este pode adicionar novos membros ao grupo partilhando a chave secreta do grupo com estes. Ou seja trata-se de um administrador a nível do sistema mas não necessariamente um verdadeiro administrador criptográfico, já que nada impede aos clientes que entram no grupo de partilhar a chave do grupo.

Este é o processo da criação do grupo:

1. Cliente corre comando `/add_group`, e datagrama `add_group()` é enviado ao servidor com nome do grupo.

2. Servidor verifica que não existe outro grupo com esse nome e adiciona na sua lista de groups um grupo com o dono denominado pelo nome do cliente e uma lista de membros preenchida atualmente apenas pelo cliente. A seguir envia uma confirmação ao cliente que o grupo foi adicionado.

3. Ao receber a confirmação, o cliente gera uma chave aleatória e guarda-a como chave do grupo. Note-se que a geração foi feita exclusivamente na parte do cliente e neste momento apenas este tem acesso a esta chave secreta. 

Assim, o grupo foi efetivamente criado e estará pronto para receber novos membros.

O processo de adicionar um membro é:

1. Para partilhar chave de grupo com membro que está a ser adicionado, precisa de ter sessão com esse cliente para poder enviar chave de forma segura.

2. Portanto existindo essa sessão, faz mesmo processo de encriptação descrito anteriormente com essa chave de sessão para encriptar a chave do grupo e cria um payload com o nome do grupo e o resultado da encriptação que envia para o servidor através do datagrama `group_invite()`.

3. O servidor verifica que o cliente que está a tentar adicionar outro cliente de facto é o dono/administrador do grupo. Se for o caso reencaminha conteúdo encriptado para o cliente que está a ser adicionado através do datagrama `group_invite_deliver()`.

4. Ao receber datagrama, o cliente que está a ser adicionado verifica se tem sessão com administrador, se não for o caso envia o datagrama `no_session_inform()` ao servidor. Se tiver uma sessão válida com este, faz o mesmo processo já explicado anteriormente de desencriptação com a chave de sessão e guarda a chave do novo grupo desencriptada para utilizar posteriormente nas mensagens de grupo. Depois manda confirmação ao servidor da aceitação do pedido através do datagrama `accept_invite()`.

5. Ao receber confirmação do cliente adicionado ao grupo, servidor adiciona-o à lista de membros do grupo.

O processo de mandar uma mensagem de grupo é:

1. O cliente cria um payload com o seu nome e o nome do grupo e faz a encriptação com a chave do específico grupo e envia ambos para o servidor através do datagrama `group_msg()`.

2. O servidor recebe o datagrama e verifica que o grupo de facto existe e que o enviador está no grupo. Posteriormente percorre a lista de membros e reencaminha o payload para todos estes (com a exceção do membro que envia a mensagem) o payload e o conteúdo encriptado também através do datagrama `group_msg()`.

3. Um cliente membro ao receber uma mensagem de grupo e verifica que de facto têm a chave do grupo. Se for o caso, desencripta a mensagem com essa chave. Note-se que a mensagem é imprimida em cada membro que recebe a mensagem com o nome do enviador que estava no payload, sendo portanto claro para o recetor qual dos membros do grupo enviou a mensagem.


O cliente tem ainda a opção de sair de um grupo através do comando `/leave_group` e listar os grupos em que está presente com `/list_groups`.
Note-se que se o administrador de um grupo sair deste o grupo ficará bloqueado de ter mais membros adicionados. Note-se ainda que as mensagens de grupo não involvem qualquer tipo de forward secrecy por razões de simplificação. A implementação envolveria a recriação da chave do grupo e redistribuição desta por todos membros do grupo. A estratégia de redistribuição de forma otimizada, funcional e segura seria um interessante foco para futura análise.

De forma a permitir que sessões previamente estabelecidas possam ser reutilizadas após reinício da aplicação, as chaves de sessão e chaves de grupo são armazenadas localmente no cliente. No entanto, estas chaves nunca são persistidas em texto simples. Após autenticação do utilizador, a password introduzida é utilizada para derivar uma chave criptográfica local `local_storage_key` através de um KDF baseado em HKDF com SHA-256.

É importante de notar que o estabelecimento do limite de mensagens de cada sessão (forward secrecy) implica que mesmo após um atacante tenha acesso direto ao sistema de ficheiros do utilizador e conheça a sua password, este apenas vai conseguir recuperar até a esse limite de mensagens, já que apenas as sessões válidas/ativas são persistidas e as antigas são automaticamente apagadas após o limite ser atingido.

O sistema implementa suporte para mensagens offline, permitindo que mensagens e convites sejam entregues mesmo quando o destinatário não se encontra ligado ao servidor. Quando um cliente envia uma mensagem através do comando `/msg`, o servidor verifica se o utilizador destinatário possui uma ligação ativa. Caso o destinatário esteja online, o datagrama é imediatamente reencaminhado para o cliente.

Caso contrário, o servidor armazena o datagrama recebido numa estrutura persistente `offline_messages` associada ao utilizador destinatário. O armazenamento inclui o conteúdo encriptado da mensagem exatamente como foi recebido pelo servidor, sem qualquer processo de desencriptação intermédio.

Desta forma, o servidor atua apenas como intermediário de armazenamento e encaminhamento, mantendo as garantias de confidencialidade ponta-a-ponta (E2EE). Como as mensagens já se encontram cifradas com AES-GCM utilizando a chave de sessão derivada via ECDH, o servidor não possui capacidade para aceder ao conteúdo original das mensagens armazenadas. Após autenticação bem-sucedida de um utilizador, o servidor verifica automaticamente se existem mensagens pendentes associadas a esse utilizador. Caso existam, o servidor envia uma notificação ao cliente e procede ao reencaminhamento sequencial de todos os datagramas armazenados. Após entrega bem-sucedida, as mensagens offline são removidas do armazenamento persistente.

Devido ao armazenamento das chaves de sessão, o cliente recetor é capaz de recuperar a chave de sessão que tinha com o cliente enviador e desencriptar a mensagem pendente.

# Análise Crítica da Solução

A solução desenvolvida apresenta uma arquitetura relativamente robusta para um sistema de comunicação segura, integrando múltiplos mecanismos criptográficos modernos e aplicando boas práticas de segurança ao nível da autenticação, estabelecimento de sessões e proteção das mensagens. A utilização combinada de TLS, E2EE, criptografia assimétrica e criptografia simétrica permitiu construir um sistema com garantias relevantes de confidencialidade, integridade, autenticidade e resistência parcial a compromissões futuras de chaves.

Um dos principais pontos positivos da solução é a separação clara entre segurança ao nível do transporte e segurança ponta-a-ponta. Apesar da comunicação cliente-servidor já ocorrer sobre TLS, a implementação adicional de encriptação E2EE garante que o servidor não possui acesso ao conteúdo das mensagens trocadas entre utilizadores. Esta abordagem aproxima o sistema de arquiteturas utilizadas em aplicações modernas de mensagens seguras.

A utilização de Ed25519 para assinaturas digitais e X25519 para estabelecimento de segredos partilhados representa igualmente uma escolha tecnicamente adequada. Ambas as curvas pertencem à família Curve25519, amplamente utilizada devido ao seu bom equilíbrio entre desempenho, simplicidade e segurança criptográfica. A derivação de chaves através de HKDF-SHA256 e a utilização de AES-GCM como algoritmo de encriptação autenticada seguem também recomendações modernas da comunidade criptográfica.

Outro aspeto relevante é a implementação de forward secrecy através da utilização de chaves efémeras e limitação do número de mensagens por sessão. Esta abordagem reduz significativamente o impacto da eventual compromissão de uma chave de sessão, já que apenas um conjunto limitado de mensagens poderá ser comprometido. A decisão de apagar automaticamente sessões após determinado número de mensagens demonstra preocupação com a minimização da exposição criptográfica ao longo do tempo.

A funcionalidade de mensagens offline foi integrada de forma consistente com o modelo E2EE. O servidor apenas armazena conteúdos previamente encriptados, não possuindo capacidade para desencriptar as mensagens persistidas. Isto permite manter as propriedades de confidencialidade mesmo em cenários onde o servidor armazena temporariamente mensagens pendentes.

Apesar dos aspetos positivos, existem algumas limitações e fragilidades inerentes à solução implementada.

Uma das principais limitações encontra-se no facto de o servidor atuar simultaneamente como intermediário de comunicação e autoridade certificadora. Embora esta abordagem simplifique significativamente a implementação e gestão de certificados, cria também um ponto central de confiança. Caso a chave privada da CA do servidor seja comprometida, um atacante poderá emitir certificados falsos e executar ataques de impersonação (man-in-the-middle) entre clientes.

A segurança do AES-GCM depende criticamente da não reutilização de nonces com a mesma chave. Embora a utilização de nonces aleatórios de 96 bits torne colisões extremamente improváveis, abordagens determinísticas baseadas em contadores poderiam oferecer garantias formais mais fortes.

As mensagens de grupo representam igualmente um ponto de simplificação relevante. A utilização de uma única chave simétrica partilhada entre todos os membros simplifica a implementação, mas introduz limitações importantes. Qualquer membro do grupo pode redistribuir a chave a terceiros, e a saída de membros não implica rotação automática da chave do grupo. Isto significa que membros removidos podem continuar a desencriptar mensagens futuras caso mantenham cópia da chave anteriormente distribuída.

Nas mensagens de grupo, a autenticação criptográfica individual dos membros não é garantida. Como todos os participantes partilham a mesma chave simétrica do grupo, qualquer membro pode potencialmente forjar mensagens aparentando ser outro participante. Adicionalmente, nada impede que um membro legítimo partilhe externamente a chave do grupo com utilizadores não autorizados, permitindo-lhes desencriptar futuras mensagens do grupo sem conhecimento dos restantes participantes.

Adicionalmente, o sistema não implementa proteção explícita contra alguns ataques ao nível do protocolo, nomeadamente:

- replay attacks
- análise de tráfego
- correlação temporal de mensagens
- flooding ou negação de serviço
- comprometimento do endpoint do cliente

Tal como na maioria dos sistemas E2EE, a segurança global continua fortemente dependente da segurança do dispositivo cliente. 

Apesar destas limitações, a solução apresenta uma arquitetura coerente e tecnicamente sólida para o contexto académico do projeto. Foram corretamente aplicados diversos conceitos fundamentais de Segurança de Sistemas Informáticos, incluindo:

- autenticação criptográfica
- gestão de identidades
- derivação segura de chaves
- encriptação autenticada
- estabelecimento seguro de sessões
- persistência protegida de material criptográfico
- forward secrecy
- comunicação ponta-a-ponta

# Conclusão

O projeto demonstra uma integração consistente entre teoria criptográfica e implementação prática, conseguindo equilibrar segurança, simplicidade e funcionalidade dentro do âmbito proposto.