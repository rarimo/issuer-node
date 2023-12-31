import { Link } from "react-router-dom";

import { ReactComponent as IconLogo } from "src/assets/rarimo-logo.svg";
import { ROOT_PATH } from "src/utils/constants";

export function LogoLink() {
    return (
        <Link to={ROOT_PATH}>
            <IconLogo className='app-logo' />
        </Link>
    );
}