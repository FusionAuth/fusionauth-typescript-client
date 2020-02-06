"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const FusionAuthClient_1 = require("./FusionAuthClient");
const authClient = new FusionAuthClient_1.FusionAuthClient('P7CYlYl0XI2Lv_Lmm8ZPvg2aCVnqFOgvhQmC2z5xS8I', 'https://auth.kultifyapp.com');
const result = authClient.searchUsersByIds([
    '3b5e630a-c781-44dd-9370-62cb8d08cdde',
    '672b3ea3-3b46-4cb5-a110-1a5a19855b41'
]);
result
    .then(res => console.log(res))
    .catch(err => console.error(JSON.stringify(err)));
//# sourceMappingURL=test.js.map