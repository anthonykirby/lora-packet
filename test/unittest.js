describe("unit tests", function () {
    this.timeout(1000);

    require('./test_parse.js')();
    require('./test_mic.js')();
    require('./test_decrypt.js')();
});
