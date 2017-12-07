describe("unit tests", function () {
    this.timeout(1000);

    require('./test_parse.js')();
    require('./test_construct.js')();
    require('./test_mic.js')();
    require('./test_decrypt.js')();
    require('./test_keygen.js')();
    require('./test_github_issue17.js')();
});
