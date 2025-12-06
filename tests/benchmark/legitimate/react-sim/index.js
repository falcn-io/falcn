// index.js
// Standard UI library code - should NOT trigger heuristics

module.exports = {
    Component: class Component {
        constructor(props) {
            this.props = props;
        }
        render() {
            return null;
        }
    },
    createElement: function (type, props, children) {
        return { type, props, children };
    },
    useState: function (initial) {
        return [initial, function () { }];
    }
};
