2024年心血來潮開始的自主學習，
從零開始探討動態加密的技術與概念，
一群菜雞學生所做，
一切虛心受教哈哈。

### 此專案在做甚麼？

### 版本一：
#### 伺服器端：
1. 生成 RSA 公鑰和私鑰。
2. 將 RSA 公鑰發送給客戶端。
3. 接收並解密由客戶端加密的 AES 密鑰，並用這個 AES 密鑰解密後續的訊息。

#### 客戶端端：
1. 接收伺服器端的 RSA 公鑰。
2. 使用 RSA 公鑰加密 AES 密鑰，並將加密後的 AES 密鑰傳送給伺服器。
3. 使用解密後的 AES 密鑰加密訊息，並將加密訊息發送回伺服器。


### 版本二
#### 伺服器端的任務：
伺服器負責生成、管理 AES 密鑰，並根據客戶端的需求來加密資料或進行密鑰傳輸。具體來說，它的任務包括生成 AES 密鑰、加密資料、接收客戶端的請求以及傳送加密結果。

#### 客戶端的任務：
客戶端的主要任務是與伺服器通信，選擇要訪問的資料，接收來自伺服器的加密資料並進行解密。客戶端也負責存取伺服器生成的密鑰（通常是 AES 密鑰），以便能正確地解密收到的加密資料。

#### 時間線及雙方的區別
##### 1. 伺服器端生成 AES 密鑰
伺服器端：
    生成多組 AES 密鑰：伺服器會在一開始生成多組 AES 密鑰，這些密鑰會被存儲起來供後續加密使用。通常，會生成多組密鑰（如 10 組），以便後續每次加密資料時能隨機選擇其中一個密鑰進行加密。
    準備預存資料：伺服器還會準備多組預存資料（例如 5 組），這些資料會根據客戶端的請求進行加密和傳輸。

客戶端：
    等待與伺服器建立連接：客戶端不進行任何密鑰生成行為，只等待伺服器端的密鑰生成完成，並準備建立通信。

##### 2. RSA 公鑰的交換
伺服器端：
    等待接收客戶端的 RSA 公鑰：在伺服器生成 AES 密鑰之後，伺服器等待客戶端發送其 RSA 公鑰。伺服器需要這個公鑰來加密後續傳輸給客戶端的 AES 密鑰或加密的資料。

客戶端：
    生成 RSA 金鑰對：客戶端會生成一對 RSA 公私鑰，這個 RSA 密鑰對將用來加密和解密伺服器傳來的 AES 密鑰或資料。
    將 RSA 公鑰發送給伺服器：客戶端會將自己的 RSA 公鑰發送給伺服器，這樣伺服器可以使用這個公鑰來加密 AES 密鑰並傳給客戶端。

##### 3. 客戶端選擇資料請求
伺服器端：
    等待客戶端請求資料：伺服器處於等待狀態，直到客戶端發送一個請求，告知伺服器它想讀取哪一組預存的資料。

客戶端：
    向伺服器發送請求：客戶端輸入自己想讀取的資料編號，並將這個編號發送給伺服器。這個請求告訴伺服器要取回哪一組預存的資料進行加密。

##### 4. 伺服器使用 AES 密鑰加密資料並傳輸
伺服器端：
    隨機選擇一組 AES 密鑰：伺服器會從事先生成的 AES 密鑰中隨機選擇一組密鑰，這個密鑰將被用來加密客戶端請求的資料。
    加密資料：伺服器使用選擇的 AES 密鑰對客戶端請求的資料進行加密。
    加密資料和 AES 密鑰的處理：
        1. 加密資料：伺服器用隨機選擇的 AES 密鑰加密資料。
        2. 傳輸密鑰：伺服器使用客戶端提供的 RSA 公鑰加密這個 AES 密鑰，然後傳送給客戶端。
    傳送加密結果給客戶端：伺服器將加密後的資料以及使用的 AES 密鑰傳送給客戶端。資料是用 AES 加密的，而密鑰是用 RSA 加密的。

客戶端：
    接收加密的資料：客戶端會收到兩部分內容：
    加密的 AES 密鑰：這個密鑰是用客戶端的 RSA 公鑰加密的，因此只有客戶端能解密。
    加密的資料：這是用 AES 密鑰加密的，客戶端需要解密密鑰後，才能進一步解密資料。

##### 5. 客戶端解密 AES 密鑰與資料
伺服器端：
    處於空閒狀態：在這個步驟中，伺服器不再進行進一步操作，等待客戶端解密結果。

客戶端：
    解密 AES 密鑰：客戶端使用自己的 RSA 私鑰來解密伺服器發送的 AES 密鑰。
    使用 AES 密鑰解密資料：一旦 AES 密鑰解密成功，客戶端就使用這個 AES 密鑰對收到的加密資料進行解密，獲取原始資料。

#### 伺服器與客戶端動態加密中的區別：
##### 伺服器端：
1. 生成 AES 密鑰並進行管理。
2. 根據客戶端請求選擇資料，並隨機使用 AES 密鑰加密資料。
3. 使用 RSA 公鑰加密 AES 密鑰，並將加密資料和加密密鑰發送給客戶端。

##### 客戶端：
1. 生成 RSA 金鑰對，並發送 RSA 公鑰給伺服器。
2. 請求伺服器發送加密資料。
3. 解密伺服器發送的 AES 密鑰，然後使用這個密鑰解密加密資料。

#### 時間線上的步驟：
1. 伺服器生成 AES 密鑰 → 客戶端生成 RSA 金鑰對。
2. 客戶端發送 RSA 公鑰 → 伺服器接收並等待客戶端請求資料。
3. 客戶端選擇資料 → 伺服器隨機選擇 AES 密鑰加密資料。
4. 伺服器用 RSA 公鑰加密 AES 密鑰並傳送資料 → 客戶端接收並解密 AES 密鑰。
5. 客戶端使用 AES 密鑰解密資料 → 伺服器等待新的請求或結束。