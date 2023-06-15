import { Link } from "react-router-dom";
import Employee from "./Employee";

const Editor = () => {
    return (
        <section>
            <Employee />

            <div className="flexGrow">
                <Link to="/">Home</Link>
            </div>
        </section>
    );
};

export default Editor;
