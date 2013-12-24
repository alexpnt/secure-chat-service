import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/*
 * A lookup table used to retrieve existing clients and their session keys. It is also used to add new entries.
 */
public class LookupTable implements Serializable{
	private static final long serialVersionUID = 1L;
	
	private List<Record> table;

	LookupTable(){
		super();
		this.table = new ArrayList<Record>();
	}
	
	/*
	 * Adds a new record
	 */
	public boolean addRecord(Record record){
		for(Record r:table){
			if(r.getUsername().compareToIgnoreCase(record.getUsername())==0){
				return false;
			}
		}
		return table.add(record);
	}
	
	/*
	 * Gets a specific table record(a client)
	 */
	public Record getRecord(String username){
		for(Record record:table){
			if(record.getUsername().compareToIgnoreCase(username)==0){
				return record;
			}
		}
		return null;
	}
	
	/*
	 * Updates a table entry with a new shared key and a new timestamp
	 */
	public Record updateRecord(Record record){
		for(Record r:table){
			if(r.getUsername().compareToIgnoreCase(record.getUsername())==0){
				r.setSessionKey(record.getSessionKey());
				r.setTimeStamp(record.getTimeStamp());
			}
		}
		return null;
	}

	public List<Record> getTable() {
		return table==null? new ArrayList<Record>():table;
	}

	public void setTable(List<Record> table) {
		this.table = table;
	}
}
