const path = require('path');

module.exports = {
    entry: './src/resultsDisplay/resultsTab.ts',
    output: {
        filename: 'resultsTab.js',
        path: path.resolve(__dirname, 'dist'),
    },
    resolve: {
        extensions: ['.ts', '.js'],
    },
    module: {
        rules: [
            {
                test: /\.ts$/,
                use: 'ts-loader',
                exclude: /node_modules/,
            },
        ],
    },
    mode: 'production',
    devtool: 'source-map',
};
