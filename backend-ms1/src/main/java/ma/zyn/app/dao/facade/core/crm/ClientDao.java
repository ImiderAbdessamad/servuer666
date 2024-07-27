package ma.zyn.app.dao.facade.core.crm;

import ma.zyn.app.zynerator.repository.AbstractRepository;
import ma.zyn.app.bean.core.crm.Client;
import org.springframework.stereotype.Repository;
import java.util.List;


@Repository
public interface ClientDao extends AbstractRepository<Client,Long>  {

    Client findByUsername(String username);


}
